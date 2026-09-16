rule TTP_XOR_WriteProcessMemory_3582 {
  strings:
    $key_3582 = { 62 f0 [2] 50 d2 [2] 56 e7 [2] 78 e7 [2] 47 fb }

  condition:
    any of them
}