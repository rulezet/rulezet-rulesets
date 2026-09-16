rule TTP_XOR_WriteProcessMemory_3372 {
  strings:
    $key_3372 = { 64 00 [2] 56 22 [2] 50 17 [2] 7e 17 [2] 41 0b }

  condition:
    any of them
}