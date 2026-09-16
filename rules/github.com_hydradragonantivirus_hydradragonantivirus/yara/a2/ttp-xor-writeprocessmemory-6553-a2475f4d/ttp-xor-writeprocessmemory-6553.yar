rule TTP_XOR_WriteProcessMemory_6553 {
  strings:
    $key_6553 = { 32 21 [2] 00 03 [2] 06 36 [2] 28 36 [2] 17 2a }

  condition:
    any of them
}