rule TTP_XOR_WriteProcessMemory_5713 {
  strings:
    $key_5713 = { 00 61 [2] 32 43 [2] 34 76 [2] 1a 76 [2] 25 6a }

  condition:
    any of them
}