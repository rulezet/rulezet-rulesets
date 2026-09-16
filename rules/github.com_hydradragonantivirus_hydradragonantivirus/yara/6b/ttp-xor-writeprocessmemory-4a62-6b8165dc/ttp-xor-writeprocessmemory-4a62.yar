rule TTP_XOR_WriteProcessMemory_4a62 {
  strings:
    $key_4a62 = { 1d 10 [2] 2f 32 [2] 29 07 [2] 07 07 [2] 38 1b }

  condition:
    any of them
}