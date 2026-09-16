rule TTP_XOR_WriteProcessMemory_a000 {
  strings:
    $key_a000 = { f7 72 [2] c5 50 [2] c3 65 [2] ed 65 [2] d2 79 }

  condition:
    any of them
}