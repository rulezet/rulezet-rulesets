rule sig_20150821_261f19fd4b2b0007f63e43291b044f9a {
  meta:
    description = "datamaliciousorder - file 20150821_261f19fd4b2b0007f63e43291b044f9a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5128e41c437c79e313e27a39ecfa3738358fc8a90c8a212a5d49fe27540e35b5"

  strings:
    $s1 = "print (mEkejggx5);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}