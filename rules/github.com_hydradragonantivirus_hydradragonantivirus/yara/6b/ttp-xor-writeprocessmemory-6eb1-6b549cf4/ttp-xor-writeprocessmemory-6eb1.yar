rule TTP_XOR_WriteProcessMemory_6eb1 {
  strings:
    $key_6eb1 = { 39 c3 [2] 0b e1 [2] 0d d4 [2] 23 d4 [2] 1c c8 }

  condition:
    any of them
}