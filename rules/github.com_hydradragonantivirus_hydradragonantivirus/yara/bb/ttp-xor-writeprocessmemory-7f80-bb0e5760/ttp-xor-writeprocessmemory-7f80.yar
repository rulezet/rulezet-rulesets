rule TTP_XOR_WriteProcessMemory_7f80 {
  strings:
    $key_7f80 = { 28 f2 [2] 1a d0 [2] 1c e5 [2] 32 e5 [2] 0d f9 }

  condition:
    any of them
}