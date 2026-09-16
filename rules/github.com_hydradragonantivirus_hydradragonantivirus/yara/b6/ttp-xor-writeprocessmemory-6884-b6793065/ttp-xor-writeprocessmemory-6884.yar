rule TTP_XOR_WriteProcessMemory_6884 {
  strings:
    $key_6884 = { 3f f6 [2] 0d d4 [2] 0b e1 [2] 25 e1 [2] 1a fd }

  condition:
    any of them
}