rule ttp_toolmark_physicaldrive_xor {
  meta:
    author = "stvemillertime"
    desc   = "this looks for pes with the xored toolmark PhysicalDrive which is often a handle to the ... physical drive (raw disk)"

  strings:
    $a = "PhysicalDrive" xor(0x01-0xff)
    $b = "physicaldrive" xor(0x01-0x19)
    $c = "physicaldrive" xor(0x21-0xff)
    $d = "PHYSICALDRIVE" xor(0x01-0x19)
    $e = "PHYSICALDRIVE" xor(0x21-0xff)

  condition:
    uint16be(0) == 0x4d5a
    and any of them
}