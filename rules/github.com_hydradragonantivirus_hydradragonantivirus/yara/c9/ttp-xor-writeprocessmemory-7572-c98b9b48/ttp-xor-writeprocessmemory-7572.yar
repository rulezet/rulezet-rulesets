rule TTP_XOR_WriteProcessMemory_7572 {
  strings:
    $key_7572 = { 22 00 [2] 10 22 [2] 16 17 [2] 38 17 [2] 07 0b }

  condition:
    any of them
}