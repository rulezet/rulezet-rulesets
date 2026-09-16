rule TTP_XOR_WriteProcessMemory_1a62 {
  strings:
    $key_1a62 = { 4d 10 [2] 7f 32 [2] 79 07 [2] 57 07 [2] 68 1b }

  condition:
    any of them
}