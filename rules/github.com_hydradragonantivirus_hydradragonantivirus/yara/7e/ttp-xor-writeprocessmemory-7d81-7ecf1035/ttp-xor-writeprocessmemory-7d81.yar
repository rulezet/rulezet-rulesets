rule TTP_XOR_WriteProcessMemory_7d81 {
  strings:
    $key_7d81 = { 2a f3 [2] 18 d1 [2] 1e e4 [2] 30 e4 [2] 0f f8 }

  condition:
    any of them
}