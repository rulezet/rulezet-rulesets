rule TTP_XOR_WriteProcessMemory_a7f1 {
  strings:
    $key_a7f1 = { f0 83 [2] c2 a1 [2] c4 94 [2] ea 94 [2] d5 88 }

  condition:
    any of them
}