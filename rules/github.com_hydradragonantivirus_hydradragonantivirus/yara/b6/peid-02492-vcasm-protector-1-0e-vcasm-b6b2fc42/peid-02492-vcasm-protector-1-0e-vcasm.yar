rule PEiD_02492_Vcasm_Protector_1_0e____vcasm_ {
  meta:
    description = "[Vcasm-Protector 1.0e -> vcasm]"
    ep_only     = "true"

  strings:
    $a = { EB 0A 5B 56 50 72 6F 74 65 63 74 5D }

  condition:
    $a
}