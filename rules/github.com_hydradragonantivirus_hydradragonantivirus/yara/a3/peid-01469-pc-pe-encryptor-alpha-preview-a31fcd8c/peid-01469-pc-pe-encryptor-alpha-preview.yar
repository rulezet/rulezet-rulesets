rule PEiD_01469_PC_PE_Encryptor_Alpha_preview_ {
  meta:
    description = "[PC PE Encryptor Alpha preview]"
    ep_only     = "true"

  strings:
    $a = { 53 51 52 56 57 55 E8 00 00 00 00 5D 8B CD 81 ED 33 30 40 ?? 2B 8D EE 32 40 00 83 E9 0B 89 8D F2 32 40 ?? 80 BD D1 32 40 ?? 01 0F 84 }

  condition:
    $a
}