rule PEiD_00968_kryptor_9_ {
  meta:
    description = "[kryptor 9]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 ?? ?? ?? ?? 5E B9 ?? ?? ?? ?? 2B C0 02 04 0E D3 C0 49 79 F8 41 8D 7E 2C 33 46 ?? 66 B9 }

  condition:
    $a
}