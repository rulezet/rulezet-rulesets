rule TTP_XOR_WriteProcessMemory_1592 {
  strings:
    $key_1592 = { 42 e0 [2] 70 c2 [2] 76 f7 [2] 58 f7 [2] 67 eb }

  condition:
    any of them
}