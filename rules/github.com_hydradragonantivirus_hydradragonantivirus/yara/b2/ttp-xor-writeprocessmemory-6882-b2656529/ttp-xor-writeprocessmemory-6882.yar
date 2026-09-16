rule TTP_XOR_WriteProcessMemory_6882 {
  strings:
    $key_6882 = { 3f f0 [2] 0d d2 [2] 0b e7 [2] 25 e7 [2] 1a fb }

  condition:
    any of them
}