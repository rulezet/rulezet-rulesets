rule TTP_XOR_WriteProcessMemory_7880 {
  strings:
    $key_7880 = { 2f f2 [2] 1d d0 [2] 1b e5 [2] 35 e5 [2] 0a f9 }

  condition:
    any of them
}