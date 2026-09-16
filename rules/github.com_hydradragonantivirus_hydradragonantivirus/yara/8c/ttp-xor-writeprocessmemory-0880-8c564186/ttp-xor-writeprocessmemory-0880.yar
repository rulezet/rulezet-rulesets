rule TTP_XOR_WriteProcessMemory_0880 {
  strings:
    $key_0880 = { 5f f2 [2] 6d d0 [2] 6b e5 [2] 45 e5 [2] 7a f9 }

  condition:
    any of them
}