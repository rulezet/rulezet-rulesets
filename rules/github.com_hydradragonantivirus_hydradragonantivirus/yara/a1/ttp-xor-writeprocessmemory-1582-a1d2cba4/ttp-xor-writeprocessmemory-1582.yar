rule TTP_XOR_WriteProcessMemory_1582 {
  strings:
    $key_1582 = { 42 f0 [2] 70 d2 [2] 76 e7 [2] 58 e7 [2] 67 fb }

  condition:
    any of them
}