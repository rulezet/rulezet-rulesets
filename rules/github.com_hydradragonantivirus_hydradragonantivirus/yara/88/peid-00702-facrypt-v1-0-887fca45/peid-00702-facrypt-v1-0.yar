rule PEiD_00702_FACRYPT_v1_0_ {
  meta:
    description = "[FACRYPT v1.0]"
    ep_only     = "true"

  strings:
    $a = { B9 ?? ?? B3 ?? 33 D2 BE ?? ?? 8B FE AC 32 C3 AA 49 43 32 E4 03 D0 E3 }

  condition:
    $a
}