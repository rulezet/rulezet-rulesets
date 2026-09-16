rule TTP_XOR_WriteProcessMemory_a525 {
  strings:
    $key_a525 = { f2 57 [2] c0 75 [2] c6 40 [2] e8 40 [2] d7 5c }

  condition:
    any of them
}