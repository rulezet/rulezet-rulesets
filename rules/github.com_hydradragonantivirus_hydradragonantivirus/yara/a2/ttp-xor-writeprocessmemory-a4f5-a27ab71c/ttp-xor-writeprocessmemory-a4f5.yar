rule TTP_XOR_WriteProcessMemory_a4f5 {
  strings:
    $key_a4f5 = { f3 87 [2] c1 a5 [2] c7 90 [2] e9 90 [2] d6 8c }

  condition:
    any of them
}