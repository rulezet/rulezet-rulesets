rule TTP_XOR_WriteProcessMemory_0f80 {
  strings:
    $key_0f80 = { 58 f2 [2] 6a d0 [2] 6c e5 [2] 42 e5 [2] 7d f9 }

  condition:
    any of them
}