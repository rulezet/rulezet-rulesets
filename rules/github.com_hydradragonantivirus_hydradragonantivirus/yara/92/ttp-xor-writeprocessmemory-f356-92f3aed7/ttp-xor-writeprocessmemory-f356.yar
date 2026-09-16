rule TTP_XOR_WriteProcessMemory_f356 {
  strings:
    $key_f356 = { a4 24 [2] 96 06 [2] 90 33 [2] be 33 [2] 81 2f }

  condition:
    any of them
}