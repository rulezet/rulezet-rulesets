rule TTP_XOR_WriteProcessMemory_5722 {
  strings:
    $key_5722 = { 00 50 [2] 32 72 [2] 34 47 [2] 1a 47 [2] 25 5b }

  condition:
    any of them
}