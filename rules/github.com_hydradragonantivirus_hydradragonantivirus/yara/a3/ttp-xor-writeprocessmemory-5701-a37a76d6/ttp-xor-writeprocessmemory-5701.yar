rule TTP_XOR_WriteProcessMemory_5701 {
  strings:
    $key_5701 = { 00 73 [2] 32 51 [2] 34 64 [2] 1a 64 [2] 25 78 }

  condition:
    any of them
}