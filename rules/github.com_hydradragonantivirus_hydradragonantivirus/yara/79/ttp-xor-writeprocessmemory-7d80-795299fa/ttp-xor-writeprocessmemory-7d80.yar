rule TTP_XOR_WriteProcessMemory_7d80 {
  strings:
    $key_7d80 = { 2a f2 [2] 18 d0 [2] 1e e5 [2] 30 e5 [2] 0f f9 }

  condition:
    any of them
}