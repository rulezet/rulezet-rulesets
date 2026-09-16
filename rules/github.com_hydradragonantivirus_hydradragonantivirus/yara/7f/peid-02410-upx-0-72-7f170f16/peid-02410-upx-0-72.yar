rule PEiD_02410_UPX_0_72_ {
  meta:
    description = "[UPX 0.72]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 00 00 00 00 83 CD FF 31 DB 5E }

  condition:
    $a
}