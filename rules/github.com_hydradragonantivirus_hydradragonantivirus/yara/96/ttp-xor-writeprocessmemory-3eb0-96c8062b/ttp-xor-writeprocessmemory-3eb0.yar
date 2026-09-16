rule TTP_XOR_WriteProcessMemory_3eb0 {
  strings:
    $key_3eb0 = { 69 c2 [2] 5b e0 [2] 5d d5 [2] 73 d5 [2] 4c c9 }

  condition:
    any of them
}