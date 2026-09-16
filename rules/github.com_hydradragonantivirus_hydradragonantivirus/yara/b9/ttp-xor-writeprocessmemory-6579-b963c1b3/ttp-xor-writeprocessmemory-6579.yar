rule TTP_XOR_WriteProcessMemory_6579 {
  strings:
    $key_6579 = { 32 0b [2] 00 29 [2] 06 1c [2] 28 1c [2] 17 00 }

  condition:
    any of them
}