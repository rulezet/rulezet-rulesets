rule TTP_XOR_WriteProcessMemory_2eb5 {
  strings:
    $key_2eb5 = { 79 c7 [2] 4b e5 [2] 4d d0 [2] 63 d0 [2] 5c cc }

  condition:
    any of them
}