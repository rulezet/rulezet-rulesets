rule TTP_XOR_WriteProcessMemory_3b72 {
  strings:
    $key_3b72 = { 6c 00 [2] 5e 22 [2] 58 17 [2] 76 17 [2] 49 0b }

  condition:
    any of them
}