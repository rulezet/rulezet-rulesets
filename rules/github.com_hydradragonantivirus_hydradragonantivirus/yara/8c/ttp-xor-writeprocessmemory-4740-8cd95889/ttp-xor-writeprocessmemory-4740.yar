rule TTP_XOR_WriteProcessMemory_4740 {
  strings:
    $key_4740 = { 10 32 [2] 22 10 [2] 24 25 [2] 0a 25 [2] 35 39 }

  condition:
    any of them
}