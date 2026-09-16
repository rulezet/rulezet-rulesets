rule TTP_XOR_WriteProcessMemory_1500 {
  strings:
    $key_1500 = { 42 72 [2] 70 50 [2] 76 65 [2] 58 65 [2] 67 79 }

  condition:
    any of them
}