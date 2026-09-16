rule PEiD_02156_Stone_s_PE_Encryptor_v1_13_ {
  meta:
    description = "[Stone's PE Encryptor v1.13]"
    ep_only     = "true"

  strings:
    $a = { 55 57 56 52 51 53 E8 ?? ?? ?? ?? 5D 8B D5 81 ED 97 3B 40 ?? 2B 95 2D 3C 40 ?? 83 EA 0B 89 95 36 3C 40 ?? 01 95 24 3C 40 ?? 01 95 28 }

  condition:
    $a
}