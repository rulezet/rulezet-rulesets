rule TTP_XOR_WriteProcessMemory_6563 {
  strings:
    $key_6563 = { 32 11 [2] 00 33 [2] 06 06 [2] 28 06 [2] 17 1a }

  condition:
    any of them
}