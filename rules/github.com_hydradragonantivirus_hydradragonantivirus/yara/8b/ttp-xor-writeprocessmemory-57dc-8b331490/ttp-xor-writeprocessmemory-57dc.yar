rule TTP_XOR_WriteProcessMemory_57dc {
  strings:
    $key_57dc = { 00 ae [2] 32 8c [2] 34 b9 [2] 1a b9 [2] 25 a5 }

  condition:
    any of them
}