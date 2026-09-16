rule PEiD_00522_Encrypted_by__RSCC_286_v1_02_ {
  meta:
    description = "[Encrypted by? RSCC/286 v1.02]"
    ep_only     = "false"

  strings:
    $a = { FE 52 53 43 43 2F 31 2E 30 32 FE }

  condition:
    $a
}