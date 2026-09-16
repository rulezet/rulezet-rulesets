rule TTP_XOR_WriteProcessMemory_6eb5 {
  strings:
    $key_6eb5 = { 39 c7 [2] 0b e5 [2] 0d d0 [2] 23 d0 [2] 1c cc }

  condition:
    any of them
}