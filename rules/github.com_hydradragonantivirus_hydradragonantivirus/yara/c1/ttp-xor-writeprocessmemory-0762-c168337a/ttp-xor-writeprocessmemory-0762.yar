rule TTP_XOR_WriteProcessMemory_0762 {
  strings:
    $key_0762 = { 50 10 [2] 62 32 [2] 64 07 [2] 4a 07 [2] 75 1b }

  condition:
    any of them
}