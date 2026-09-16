rule TTP_XOR_WriteProcessMemory_27c5 {
  strings:
    $key_27c5 = { 70 b7 [2] 42 95 [2] 44 a0 [2] 6a a0 [2] 55 bc }

  condition:
    any of them
}