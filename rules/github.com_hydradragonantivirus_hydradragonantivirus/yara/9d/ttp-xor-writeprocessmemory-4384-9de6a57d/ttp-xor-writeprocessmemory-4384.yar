rule TTP_XOR_WriteProcessMemory_4384 {
  strings:
    $key_4384 = { 14 f6 [2] 26 d4 [2] 20 e1 [2] 0e e1 [2] 31 fd }

  condition:
    any of them
}