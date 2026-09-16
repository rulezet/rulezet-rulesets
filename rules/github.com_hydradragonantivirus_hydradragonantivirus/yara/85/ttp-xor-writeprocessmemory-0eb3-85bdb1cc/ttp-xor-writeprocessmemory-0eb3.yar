rule TTP_XOR_WriteProcessMemory_0eb3 {
  strings:
    $key_0eb3 = { 59 c1 [2] 6b e3 [2] 6d d6 [2] 43 d6 [2] 7c ca }

  condition:
    any of them
}