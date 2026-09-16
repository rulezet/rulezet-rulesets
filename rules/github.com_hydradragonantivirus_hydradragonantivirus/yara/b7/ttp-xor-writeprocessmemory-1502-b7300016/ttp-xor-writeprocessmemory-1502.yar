rule TTP_XOR_WriteProcessMemory_1502 {
  strings:
    $key_1502 = { 42 70 [2] 70 52 [2] 76 67 [2] 58 67 [2] 67 7b }

  condition:
    any of them
}