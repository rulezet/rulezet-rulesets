rule TTP_XOR_WriteProcessMemory_4eb3 {
  strings:
    $key_4eb3 = { 19 c1 [2] 2b e3 [2] 2d d6 [2] 03 d6 [2] 3c ca }

  condition:
    any of them
}