rule TTP_XOR_WriteProcessMemory_f302 {
  strings:
    $key_f302 = { a4 70 [2] 96 52 [2] 90 67 [2] be 67 [2] 81 7b }

  condition:
    any of them
}