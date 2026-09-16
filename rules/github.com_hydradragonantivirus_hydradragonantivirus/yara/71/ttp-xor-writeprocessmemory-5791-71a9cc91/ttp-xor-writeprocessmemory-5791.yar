rule TTP_XOR_WriteProcessMemory_5791 {
  strings:
    $key_5791 = { 00 e3 [2] 32 c1 [2] 34 f4 [2] 1a f4 [2] 25 e8 }

  condition:
    any of them
}