rule TTP_XOR_WriteProcessMemory_2882 {
  strings:
    $key_2882 = { 7f f0 [2] 4d d2 [2] 4b e7 [2] 65 e7 [2] 5a fb }

  condition:
    any of them
}