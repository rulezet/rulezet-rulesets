rule TTP_XOR_WriteProcessMemory_1596 {
  strings:
    $key_1596 = { 42 e4 [2] 70 c6 [2] 76 f3 [2] 58 f3 [2] 67 ef }

  condition:
    any of them
}