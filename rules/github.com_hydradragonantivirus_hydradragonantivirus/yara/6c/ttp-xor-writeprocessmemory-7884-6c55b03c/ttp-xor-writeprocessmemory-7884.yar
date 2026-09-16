rule TTP_XOR_WriteProcessMemory_7884 {
  strings:
    $key_7884 = { 2f f6 [2] 1d d4 [2] 1b e1 [2] 35 e1 [2] 0a fd }

  condition:
    any of them
}