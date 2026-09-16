rule TTP_XOR_WriteProcessMemory_f346 {
  strings:
    $key_f346 = { a4 34 [2] 96 16 [2] 90 23 [2] be 23 [2] 81 3f }

  condition:
    any of them
}