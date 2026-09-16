rule TTP_XOR_WriteProcessMemory_7662 {
  strings:
    $key_7662 = { 21 10 [2] 13 32 [2] 15 07 [2] 3b 07 [2] 04 1b }

  condition:
    any of them
}