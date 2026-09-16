rule TTP_XOR_WriteProcessMemory_6522 {
  strings:
    $key_6522 = { 32 50 [2] 00 72 [2] 06 47 [2] 28 47 [2] 17 5b }

  condition:
    any of them
}