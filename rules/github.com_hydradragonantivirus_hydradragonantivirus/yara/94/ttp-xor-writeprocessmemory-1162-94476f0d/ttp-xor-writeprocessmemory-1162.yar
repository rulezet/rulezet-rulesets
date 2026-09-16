rule TTP_XOR_WriteProcessMemory_1162 {
  strings:
    $key_1162 = { 46 10 [2] 74 32 [2] 72 07 [2] 5c 07 [2] 63 1b }

  condition:
    any of them
}