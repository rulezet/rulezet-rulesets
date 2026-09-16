rule TTP_XOR_WriteProcessMemory_5742 {
  strings:
    $key_5742 = { 00 30 [2] 32 12 [2] 34 27 [2] 1a 27 [2] 25 3b }

  condition:
    any of them
}