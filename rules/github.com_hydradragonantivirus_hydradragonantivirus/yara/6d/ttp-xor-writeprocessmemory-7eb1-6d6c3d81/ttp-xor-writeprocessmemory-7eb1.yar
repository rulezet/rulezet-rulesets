rule TTP_XOR_WriteProcessMemory_7eb1 {
  strings:
    $key_7eb1 = { 29 c3 [2] 1b e1 [2] 1d d4 [2] 33 d4 [2] 0c c8 }

  condition:
    any of them
}