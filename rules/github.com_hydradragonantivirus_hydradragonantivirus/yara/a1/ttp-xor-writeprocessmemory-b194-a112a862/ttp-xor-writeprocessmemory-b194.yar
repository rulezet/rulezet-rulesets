rule TTP_XOR_WriteProcessMemory_b194 {
  strings:
    $key_b194 = { e6 e6 [2] d4 c4 [2] d2 f1 [2] fc f1 [2] c3 ed }

  condition:
    any of them
}