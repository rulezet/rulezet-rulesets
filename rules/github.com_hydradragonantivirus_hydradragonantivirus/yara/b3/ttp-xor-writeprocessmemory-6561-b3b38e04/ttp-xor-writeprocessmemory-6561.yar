rule TTP_XOR_WriteProcessMemory_6561 {
  strings:
    $key_6561 = { 32 13 [2] 00 31 [2] 06 04 [2] 28 04 [2] 17 18 }

  condition:
    any of them
}