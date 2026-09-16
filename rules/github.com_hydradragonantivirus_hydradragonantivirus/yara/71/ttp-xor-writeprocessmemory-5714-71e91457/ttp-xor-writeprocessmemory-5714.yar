rule TTP_XOR_WriteProcessMemory_5714 {
  strings:
    $key_5714 = { 00 66 [2] 32 44 [2] 34 71 [2] 1a 71 [2] 25 6d }

  condition:
    any of them
}