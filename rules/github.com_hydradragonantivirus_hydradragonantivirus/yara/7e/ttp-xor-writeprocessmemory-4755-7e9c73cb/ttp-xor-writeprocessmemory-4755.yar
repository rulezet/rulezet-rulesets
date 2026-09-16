rule TTP_XOR_WriteProcessMemory_4755 {
  strings:
    $key_4755 = { 10 27 [2] 22 05 [2] 24 30 [2] 0a 30 [2] 35 2c }

  condition:
    any of them
}