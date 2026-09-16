rule TTP_XOR_WriteProcessMemory_27c0 {
  strings:
    $key_27c0 = { 70 b2 [2] 42 90 [2] 44 a5 [2] 6a a5 [2] 55 b9 }

  condition:
    any of them
}