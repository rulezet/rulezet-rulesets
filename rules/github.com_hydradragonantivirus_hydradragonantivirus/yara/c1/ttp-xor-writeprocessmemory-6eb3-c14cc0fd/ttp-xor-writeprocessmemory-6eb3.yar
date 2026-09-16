rule TTP_XOR_WriteProcessMemory_6eb3 {
  strings:
    $key_6eb3 = { 39 c1 [2] 0b e3 [2] 0d d6 [2] 23 d6 [2] 1c ca }

  condition:
    any of them
}