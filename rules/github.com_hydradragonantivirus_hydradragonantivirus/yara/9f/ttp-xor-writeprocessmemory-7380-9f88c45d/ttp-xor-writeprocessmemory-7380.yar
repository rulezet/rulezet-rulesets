rule TTP_XOR_WriteProcessMemory_7380 {
  strings:
    $key_7380 = { 24 f2 [2] 16 d0 [2] 10 e5 [2] 3e e5 [2] 01 f9 }

  condition:
    any of them
}