rule TTP_XOR_WriteProcessMemory_3eb1 {
  strings:
    $key_3eb1 = { 69 c3 [2] 5b e1 [2] 5d d4 [2] 73 d4 [2] 4c c8 }

  condition:
    any of them
}