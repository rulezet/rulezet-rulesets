rule TTP_XOR_WriteProcessMemory_6784 {
  strings:
    $key_6784 = { 30 f6 [2] 02 d4 [2] 04 e1 [2] 2a e1 [2] 15 fd }

  condition:
    any of them
}