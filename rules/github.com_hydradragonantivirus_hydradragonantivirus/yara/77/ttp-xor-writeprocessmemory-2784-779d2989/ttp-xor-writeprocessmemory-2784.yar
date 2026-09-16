rule TTP_XOR_WriteProcessMemory_2784 {
  strings:
    $key_2784 = { 70 f6 [2] 42 d4 [2] 44 e1 [2] 6a e1 [2] 55 fd }

  condition:
    any of them
}