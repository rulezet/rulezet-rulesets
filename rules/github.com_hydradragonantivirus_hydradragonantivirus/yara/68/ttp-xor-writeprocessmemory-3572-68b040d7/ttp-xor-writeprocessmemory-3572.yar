rule TTP_XOR_WriteProcessMemory_3572 {
  strings:
    $key_3572 = { 62 00 [2] 50 22 [2] 56 17 [2] 78 17 [2] 47 0b }

  condition:
    any of them
}