rule TTP_XOR_WriteProcessMemory_1550 {
  strings:
    $key_1550 = { 42 22 [2] 70 00 [2] 76 35 [2] 58 35 [2] 67 29 }

  condition:
    any of them
}