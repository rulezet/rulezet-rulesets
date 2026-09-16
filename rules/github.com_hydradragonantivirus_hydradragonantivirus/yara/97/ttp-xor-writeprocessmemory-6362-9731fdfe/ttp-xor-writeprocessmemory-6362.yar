rule TTP_XOR_WriteProcessMemory_6362 {
  strings:
    $key_6362 = { 34 10 [2] 06 32 [2] 00 07 [2] 2e 07 [2] 11 1b }

  condition:
    any of them
}