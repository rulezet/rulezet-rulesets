rule PEiD_01487_PE_Crypt_v1_02_ {
  meta:
    description = "[PE Crypt v1.02]"
    ep_only     = "false"

  strings:
    $a = { E8 ?? ?? ?? ?? 5B 83 EB 05 EB 04 52 4E 44 }

  condition:
    $a
}