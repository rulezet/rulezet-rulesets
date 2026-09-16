rule TTP_XOR_WriteProcessMemory_3880 {
  strings:
    $key_3880 = { 6f f2 [2] 5d d0 [2] 5b e5 [2] 75 e5 [2] 4a f9 }

  condition:
    any of them
}