rule TTP_XOR_WriteProcessMemory_1602 {
  strings:
    $key_1602 = { 41 70 [2] 73 52 [2] 75 67 [2] 5b 67 [2] 64 7b }

  condition:
    any of them
}