rule TTP_XOR_WriteProcessMemory_6573 {
  strings:
    $key_6573 = { 32 01 [2] 00 23 [2] 06 16 [2] 28 16 [2] 17 0a }

  condition:
    any of them
}