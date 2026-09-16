rule TTP_XOR_WriteProcessMemory_1587 {
  strings:
    $key_1587 = { 42 f5 [2] 70 d7 [2] 76 e2 [2] 58 e2 [2] 67 fe }

  condition:
    any of them
}