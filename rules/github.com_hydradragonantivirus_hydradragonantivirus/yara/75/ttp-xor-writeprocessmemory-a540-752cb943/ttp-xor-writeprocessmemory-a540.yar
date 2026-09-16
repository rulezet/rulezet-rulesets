rule TTP_XOR_WriteProcessMemory_a540 {
  strings:
    $key_a540 = { f2 32 [2] c0 10 [2] c6 25 [2] e8 25 [2] d7 39 }

  condition:
    any of them
}