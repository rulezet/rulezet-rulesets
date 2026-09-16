rule TTP_XOR_WriteProcessMemory_5eb5 {
  strings:
    $key_5eb5 = { 09 c7 [2] 3b e5 [2] 3d d0 [2] 13 d0 [2] 2c cc }

  condition:
    any of them
}