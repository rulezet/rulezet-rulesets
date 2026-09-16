rule PEiD_00631_EXECryptor_v1_5_1_x_ {
  meta:
    description = "[EXECryptor v1.5.1.x]"
    ep_only     = "true"

  strings:
    $a = { E8 24 ?? ?? ?? 8B 4C 24 0C C7 01 17 ?? 01 ?? C7 81 B8 ?? ?? ?? ?? ?? ?? ?? 31 C0 89 41 14 89 41 18 80 A1 C1 ?? ?? ?? FE C3 31 C0 64 FF 30 64 89 20 CC C3 }

  condition:
    $a
}