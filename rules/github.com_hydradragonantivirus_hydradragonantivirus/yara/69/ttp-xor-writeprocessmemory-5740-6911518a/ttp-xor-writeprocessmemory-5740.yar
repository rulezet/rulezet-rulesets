rule TTP_XOR_WriteProcessMemory_5740 {
  strings:
    $key_5740 = { 00 32 [2] 32 10 [2] 34 25 [2] 1a 25 [2] 25 39 }

  condition:
    any of them
}