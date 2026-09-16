rule PEiD_00967_kryptor_6_ {
  meta:
    description = "[kryptor 6]"
    ep_only     = "true"

  strings:
    $a = { E8 03 ?? ?? ?? E9 EB 68 58 33 D2 74 02 E9 E9 40 42 75 02 }

  condition:
    $a
}