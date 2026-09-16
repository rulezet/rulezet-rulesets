rule TTP_XOR_WriteProcessMemory_5721 {
  strings:
    $key_5721 = { 00 53 [2] 32 71 [2] 34 44 [2] 1a 44 [2] 25 58 }

  condition:
    any of them
}