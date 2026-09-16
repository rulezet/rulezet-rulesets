rule TTP_XOR_WriteProcessMemory_2662 {
  strings:
    $key_2662 = { 71 10 [2] 43 32 [2] 45 07 [2] 6b 07 [2] 54 1b }

  condition:
    any of them
}