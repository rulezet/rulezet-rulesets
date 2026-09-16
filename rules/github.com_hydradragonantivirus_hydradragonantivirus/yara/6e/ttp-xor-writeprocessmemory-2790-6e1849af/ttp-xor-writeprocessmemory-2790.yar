rule TTP_XOR_WriteProcessMemory_2790 {
  strings:
    $key_2790 = { 70 e2 [2] 42 c0 [2] 44 f5 [2] 6a f5 [2] 55 e9 }

  condition:
    any of them
}