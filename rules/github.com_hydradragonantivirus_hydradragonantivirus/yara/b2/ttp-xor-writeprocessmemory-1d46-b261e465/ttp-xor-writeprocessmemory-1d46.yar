rule TTP_XOR_WriteProcessMemory_1d46 {
  strings:
    $key_1d46 = { 4a 34 [2] 78 16 [2] 7e 23 [2] 50 23 [2] 6f 3f }

  condition:
    any of them
}