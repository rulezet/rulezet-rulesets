rule TTP_XOR_WriteProcessMemory_4884 {
  strings:
    $key_4884 = { 1f f6 [2] 2d d4 [2] 2b e1 [2] 05 e1 [2] 3a fd }

  condition:
    any of them
}