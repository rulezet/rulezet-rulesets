rule TTP_XOR_WriteProcessMemory_60b5 {
  strings:
    $key_60b5 = { 37 c7 [2] 05 e5 [2] 03 d0 [2] 2d d0 [2] 12 cc }

  condition:
    any of them
}