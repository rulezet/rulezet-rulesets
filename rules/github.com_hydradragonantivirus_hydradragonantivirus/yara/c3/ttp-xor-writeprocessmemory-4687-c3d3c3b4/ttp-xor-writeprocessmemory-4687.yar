rule TTP_XOR_WriteProcessMemory_4687 {
  strings:
    $key_4687 = { 11 f5 [2] 23 d7 [2] 25 e2 [2] 0b e2 [2] 34 fe }

  condition:
    any of them
}