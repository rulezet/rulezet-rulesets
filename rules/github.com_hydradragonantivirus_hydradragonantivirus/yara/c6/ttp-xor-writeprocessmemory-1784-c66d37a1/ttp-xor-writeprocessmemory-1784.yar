rule TTP_XOR_WriteProcessMemory_1784 {
  strings:
    $key_1784 = { 40 f6 [2] 72 d4 [2] 74 e1 [2] 5a e1 [2] 65 fd }

  condition:
    any of them
}