rule TTP_XOR_WriteProcessMemory_1eb5 {
  strings:
    $key_1eb5 = { 49 c7 [2] 7b e5 [2] 7d d0 [2] 53 d0 [2] 6c cc }

  condition:
    any of them
}