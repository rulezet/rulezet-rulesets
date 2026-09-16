rule PEiD_02173_SVK_Protector_v1_32_ {
  meta:
    description = "[SVK-Protector v1.32]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 00 00 00 00 5D 81 ED 06 00 00 00 EB 05 B8 06 36 42 00 64 A0 23 }

  condition:
    $a
}