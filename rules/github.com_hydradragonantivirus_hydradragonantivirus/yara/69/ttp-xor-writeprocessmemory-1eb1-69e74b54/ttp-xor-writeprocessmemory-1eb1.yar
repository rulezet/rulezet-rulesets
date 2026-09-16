rule TTP_XOR_WriteProcessMemory_1eb1 {
  strings:
    $key_1eb1 = { 49 c3 [2] 7b e1 [2] 7d d4 [2] 53 d4 [2] 6c c8 }

  condition:
    any of them
}