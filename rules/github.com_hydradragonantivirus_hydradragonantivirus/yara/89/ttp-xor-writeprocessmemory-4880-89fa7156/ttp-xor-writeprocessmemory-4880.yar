rule TTP_XOR_WriteProcessMemory_4880 {
  strings:
    $key_4880 = { 1f f2 [2] 2d d0 [2] 2b e5 [2] 05 e5 [2] 3a f9 }

  condition:
    any of them
}