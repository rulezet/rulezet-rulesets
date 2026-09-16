rule TTP_XOR_WriteProcessMemory_5880 {
  strings:
    $key_5880 = { 0f f2 [2] 3d d0 [2] 3b e5 [2] 15 e5 [2] 2a f9 }

  condition:
    any of them
}