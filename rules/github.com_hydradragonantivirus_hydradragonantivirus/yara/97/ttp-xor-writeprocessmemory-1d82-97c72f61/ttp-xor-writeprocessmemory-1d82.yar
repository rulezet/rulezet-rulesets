rule TTP_XOR_WriteProcessMemory_1d82 {
  strings:
    $key_1d82 = { 4a f0 [2] 78 d2 [2] 7e e7 [2] 50 e7 [2] 6f fb }

  condition:
    any of them
}