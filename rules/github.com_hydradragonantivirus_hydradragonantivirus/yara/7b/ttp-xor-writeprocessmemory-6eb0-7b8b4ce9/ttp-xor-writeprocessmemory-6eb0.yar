rule TTP_XOR_WriteProcessMemory_6eb0 {
  strings:
    $key_6eb0 = { 39 c2 [2] 0b e0 [2] 0d d5 [2] 23 d5 [2] 1c c9 }

  condition:
    any of them
}