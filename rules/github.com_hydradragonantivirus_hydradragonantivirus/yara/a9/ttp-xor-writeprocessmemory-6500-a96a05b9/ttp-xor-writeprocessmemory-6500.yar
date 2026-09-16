rule TTP_XOR_WriteProcessMemory_6500 {
  strings:
    $key_6500 = { 32 72 [2] 00 50 [2] 06 65 [2] 28 65 [2] 17 79 }

  condition:
    any of them
}