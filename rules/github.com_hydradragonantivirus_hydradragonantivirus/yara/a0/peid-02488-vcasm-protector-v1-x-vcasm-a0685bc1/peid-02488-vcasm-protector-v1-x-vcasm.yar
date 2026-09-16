rule PEiD_02488_Vcasm_Protector_V1_X____vcasm_ {
  meta:
    description = "[Vcasm Protector V1.X -> vcasm]"
    ep_only     = "true"

  strings:
    $a = { EB ?? 5B 56 50 72 6F 74 65 63 74 5D }

  condition:
    $a
}