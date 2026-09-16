rule TTP_XOR_WriteProcessMemory_5792 {
  strings:
    $key_5792 = { 00 e0 [2] 32 c2 [2] 34 f7 [2] 1a f7 [2] 25 eb }

  condition:
    any of them
}