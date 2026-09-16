rule TTP_XOR_WriteProcessMemory_2982 {
  strings:
    $key_2982 = { 7e f0 [2] 4c d2 [2] 4a e7 [2] 64 e7 [2] 5b fb }

  condition:
    any of them
}