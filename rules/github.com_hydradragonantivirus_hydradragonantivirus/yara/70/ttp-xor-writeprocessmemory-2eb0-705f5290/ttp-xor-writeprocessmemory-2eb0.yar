rule TTP_XOR_WriteProcessMemory_2eb0 {
  strings:
    $key_2eb0 = { 79 c2 [2] 4b e0 [2] 4d d5 [2] 63 d5 [2] 5c c9 }

  condition:
    any of them
}