rule TTP_XOR_WriteProcessMemory_b5f1 {
  strings:
    $key_b5f1 = { e2 83 [2] d0 a1 [2] d6 94 [2] f8 94 [2] c7 88 }

  condition:
    any of them
}