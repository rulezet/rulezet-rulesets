rule TTP_XOR_WriteProcessMemory_3882 {
  strings:
    $key_3882 = { 6f f0 [2] 5d d2 [2] 5b e7 [2] 75 e7 [2] 4a fb }

  condition:
    any of them
}