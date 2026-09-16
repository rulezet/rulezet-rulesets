rule TTP_XOR_WriteProcessMemory_2781 {
  strings:
    $key_2781 = { 70 f3 [2] 42 d1 [2] 44 e4 [2] 6a e4 [2] 55 f8 }

  condition:
    any of them
}