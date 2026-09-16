rule TTP_XOR_WriteProcessMemory_4d82 {
  strings:
    $key_4d82 = { 1a f0 [2] 28 d2 [2] 2e e7 [2] 00 e7 [2] 3f fb }

  condition:
    any of them
}