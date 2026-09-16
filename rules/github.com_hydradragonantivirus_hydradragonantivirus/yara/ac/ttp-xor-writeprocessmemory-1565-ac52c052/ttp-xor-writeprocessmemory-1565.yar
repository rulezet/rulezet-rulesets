rule TTP_XOR_WriteProcessMemory_1565 {
  strings:
    $key_1565 = { 42 17 [2] 70 35 [2] 76 00 [2] 58 00 [2] 67 1c }

  condition:
    any of them
}