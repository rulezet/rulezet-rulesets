rule TTP_XOR_WriteProcessMemory_5f80 {
  strings:
    $key_5f80 = { 08 f2 [2] 3a d0 [2] 3c e5 [2] 12 e5 [2] 2d f9 }

  condition:
    any of them
}