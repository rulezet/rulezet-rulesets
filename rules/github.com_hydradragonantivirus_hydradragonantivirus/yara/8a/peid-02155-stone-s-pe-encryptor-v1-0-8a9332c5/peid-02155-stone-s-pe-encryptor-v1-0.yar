rule PEiD_02155_Stone_s_PE_Encryptor_v1_0_ {
  meta:
    description = "[Stone's PE Encryptor v1.0]"
    ep_only     = "true"

  strings:
    $a = { 55 57 56 52 51 53 E8 ?? ?? ?? ?? 5D 8B D5 81 ED 63 3A 40 ?? 2B 95 C2 3A 40 ?? 83 EA 0B 89 95 CB 3A 40 ?? 8D B5 CA 3A 40 ?? 0F B6 36 }

  condition:
    $a
}