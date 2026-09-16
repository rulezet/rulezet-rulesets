rule TTP_XOR_WriteProcessMemory_4682 {
  strings:
    $key_4682 = { 11 f0 [2] 23 d2 [2] 25 e7 [2] 0b e7 [2] 34 fb }

  condition:
    any of them
}