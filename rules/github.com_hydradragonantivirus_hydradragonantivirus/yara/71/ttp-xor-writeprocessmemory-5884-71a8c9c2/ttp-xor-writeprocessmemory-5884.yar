rule TTP_XOR_WriteProcessMemory_5884 {
  strings:
    $key_5884 = { 0f f6 [2] 3d d4 [2] 3b e1 [2] 15 e1 [2] 2a fd }

  condition:
    any of them
}