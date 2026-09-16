rule TTP_XOR_WriteProcessMemory_3eb3 {
  strings:
    $key_3eb3 = { 69 c1 [2] 5b e3 [2] 5d d6 [2] 73 d6 [2] 4c ca }

  condition:
    any of them
}