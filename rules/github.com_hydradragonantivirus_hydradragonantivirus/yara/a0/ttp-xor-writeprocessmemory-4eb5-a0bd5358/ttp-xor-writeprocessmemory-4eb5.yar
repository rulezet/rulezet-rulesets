rule TTP_XOR_WriteProcessMemory_4eb5 {
  strings:
    $key_4eb5 = { 19 c7 [2] 2b e5 [2] 2d d0 [2] 03 d0 [2] 3c cc }

  condition:
    any of them
}