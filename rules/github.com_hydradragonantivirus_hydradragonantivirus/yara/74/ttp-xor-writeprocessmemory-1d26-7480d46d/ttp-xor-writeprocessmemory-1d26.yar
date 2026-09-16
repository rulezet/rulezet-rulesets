rule TTP_XOR_WriteProcessMemory_1d26 {
  strings:
    $key_1d26 = { 4a 54 [2] 78 76 [2] 7e 43 [2] 50 43 [2] 6f 5f }

  condition:
    any of them
}