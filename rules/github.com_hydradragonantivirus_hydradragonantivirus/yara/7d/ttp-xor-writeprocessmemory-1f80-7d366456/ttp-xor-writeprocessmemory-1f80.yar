rule TTP_XOR_WriteProcessMemory_1f80 {
  strings:
    $key_1f80 = { 48 f2 [2] 7a d0 [2] 7c e5 [2] 52 e5 [2] 6d f9 }

  condition:
    any of them
}