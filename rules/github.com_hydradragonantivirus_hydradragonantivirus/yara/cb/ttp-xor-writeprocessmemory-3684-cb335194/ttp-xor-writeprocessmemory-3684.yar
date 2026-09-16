rule TTP_XOR_WriteProcessMemory_3684 {
  strings:
    $key_3684 = { 61 f6 [2] 53 d4 [2] 55 e1 [2] 7b e1 [2] 44 fd }

  condition:
    any of them
}