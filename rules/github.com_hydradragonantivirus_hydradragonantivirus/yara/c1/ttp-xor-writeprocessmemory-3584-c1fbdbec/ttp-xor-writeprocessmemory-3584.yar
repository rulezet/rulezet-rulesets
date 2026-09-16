rule TTP_XOR_WriteProcessMemory_3584 {
  strings:
    $key_3584 = { 62 f6 [2] 50 d4 [2] 56 e1 [2] 78 e1 [2] 47 fd }

  condition:
    any of them
}