rule TTP_XOR_WriteProcessMemory_6f80 {
  strings:
    $key_6f80 = { 38 f2 [2] 0a d0 [2] 0c e5 [2] 22 e5 [2] 1d f9 }

  condition:
    any of them
}