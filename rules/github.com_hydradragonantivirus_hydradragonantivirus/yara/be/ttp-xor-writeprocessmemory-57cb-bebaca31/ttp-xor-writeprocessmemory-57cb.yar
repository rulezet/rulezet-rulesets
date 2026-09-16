rule TTP_XOR_WriteProcessMemory_57cb {
  strings:
    $key_57cb = { 00 b9 [2] 32 9b [2] 34 ae [2] 1a ae [2] 25 b2 }

  condition:
    any of them
}