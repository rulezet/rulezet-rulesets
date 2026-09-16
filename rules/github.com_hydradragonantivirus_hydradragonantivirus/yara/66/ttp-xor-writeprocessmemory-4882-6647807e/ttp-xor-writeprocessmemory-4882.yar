rule TTP_XOR_WriteProcessMemory_4882 {
  strings:
    $key_4882 = { 1f f0 [2] 2d d2 [2] 2b e7 [2] 05 e7 [2] 3a fb }

  condition:
    any of them
}