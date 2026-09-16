rule TTP_XOR_WriteProcessMemory_3884 {
  strings:
    $key_3884 = { 6f f6 [2] 5d d4 [2] 5b e1 [2] 75 e1 [2] 4a fd }

  condition:
    any of them
}