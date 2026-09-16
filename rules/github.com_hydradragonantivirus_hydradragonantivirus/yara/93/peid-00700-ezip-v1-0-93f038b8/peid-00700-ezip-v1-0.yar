rule PEiD_00700_EZIP_v1_0_ {
  meta:
    description = "[EZIP v1.0]"
    ep_only     = "true"

  strings:
    $a = { E9 19 32 00 00 E9 7C 2A 00 00 E9 19 24 00 00 E9 FF 23 00 00 E9 1E 2E 00 00 E9 88 2E 00 00 E9 2C }

  condition:
    $a
}