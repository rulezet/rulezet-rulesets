rule TTP_XOR_WriteProcessMemory_f322 {
  strings:
    $key_f322 = { a4 50 [2] 96 72 [2] 90 47 [2] be 47 [2] 81 5b }

  condition:
    any of them
}