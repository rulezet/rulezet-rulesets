rule TTP_XOR_WriteProcessMemory_4eb2 {
  strings:
    $key_4eb2 = { 19 c0 [2] 2b e2 [2] 2d d7 [2] 03 d7 [2] 3c cb }

  condition:
    any of them
}