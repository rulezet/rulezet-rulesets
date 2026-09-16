rule TTP_XOR_WriteProcessMemory_0eb0 {
  strings:
    $key_0eb0 = { 59 c2 [2] 6b e0 [2] 6d d5 [2] 43 d5 [2] 7c c9 }

  condition:
    any of them
}