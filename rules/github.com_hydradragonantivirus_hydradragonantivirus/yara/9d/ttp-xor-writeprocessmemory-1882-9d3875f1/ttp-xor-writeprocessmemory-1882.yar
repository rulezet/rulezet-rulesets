rule TTP_XOR_WriteProcessMemory_1882 {
  strings:
    $key_1882 = { 4f f0 [2] 7d d2 [2] 7b e7 [2] 55 e7 [2] 6a fb }

  condition:
    any of them
}