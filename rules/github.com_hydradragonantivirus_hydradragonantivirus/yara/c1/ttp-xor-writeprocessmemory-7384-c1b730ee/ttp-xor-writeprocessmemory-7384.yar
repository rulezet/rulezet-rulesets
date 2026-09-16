rule TTP_XOR_WriteProcessMemory_7384 {
  strings:
    $key_7384 = { 24 f6 [2] 16 d4 [2] 10 e1 [2] 3e e1 [2] 01 fd }

  condition:
    any of them
}