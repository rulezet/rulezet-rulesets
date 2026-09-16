rule TTP_XOR_WriteProcessMemory_57dd {
  strings:
    $key_57dd = { 00 af [2] 32 8d [2] 34 b8 [2] 1a b8 [2] 25 a4 }

  condition:
    any of them
}