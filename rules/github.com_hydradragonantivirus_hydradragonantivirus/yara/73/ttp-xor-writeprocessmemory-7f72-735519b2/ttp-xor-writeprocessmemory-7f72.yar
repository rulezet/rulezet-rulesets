rule TTP_XOR_WriteProcessMemory_7f72 {
  strings:
    $key_7f72 = { 28 00 [2] 1a 22 [2] 1c 17 [2] 32 17 [2] 0d 0b }

  condition:
    any of them
}