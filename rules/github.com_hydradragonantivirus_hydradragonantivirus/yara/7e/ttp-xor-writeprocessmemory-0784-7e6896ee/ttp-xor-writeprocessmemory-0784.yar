rule TTP_XOR_WriteProcessMemory_0784 {
  strings:
    $key_0784 = { 50 f6 [2] 62 d4 [2] 64 e1 [2] 4a e1 [2] 75 fd }

  condition:
    any of them
}