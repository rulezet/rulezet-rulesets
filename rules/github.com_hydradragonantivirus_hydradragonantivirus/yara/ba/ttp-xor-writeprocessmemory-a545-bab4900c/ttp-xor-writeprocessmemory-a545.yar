rule TTP_XOR_WriteProcessMemory_a545 {
  strings:
    $key_a545 = { f2 37 [2] c0 15 [2] c6 20 [2] e8 20 [2] d7 3c }

  condition:
    any of them
}