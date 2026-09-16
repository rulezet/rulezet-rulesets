rule TTP_XOR_WriteProcessMemory_5d81 {
  strings:
    $key_5d81 = { 0a f3 [2] 38 d1 [2] 3e e4 [2] 10 e4 [2] 2f f8 }

  condition:
    any of them
}