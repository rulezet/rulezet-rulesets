rule TTP_XOR_WriteProcessMemory_1886 {
  strings:
    $key_1886 = { 4f f4 [2] 7d d6 [2] 7b e3 [2] 55 e3 [2] 6a ff }

  condition:
    any of them
}