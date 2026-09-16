rule TTP_XOR_WriteProcessMemory_6781 {
  strings:
    $key_6781 = { 30 f3 [2] 02 d1 [2] 04 e4 [2] 2a e4 [2] 15 f8 }

  condition:
    any of them
}