rule TTP_XOR_WriteProcessMemory_a4f1 {
  strings:
    $key_a4f1 = { f3 83 [2] c1 a1 [2] c7 94 [2] e9 94 [2] d6 88 }

  condition:
    any of them
}