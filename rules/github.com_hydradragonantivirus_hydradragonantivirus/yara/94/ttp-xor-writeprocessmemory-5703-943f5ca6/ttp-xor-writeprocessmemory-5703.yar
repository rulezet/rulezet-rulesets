rule TTP_XOR_WriteProcessMemory_5703 {
  strings:
    $key_5703 = { 00 71 [2] 32 53 [2] 34 66 [2] 1a 66 [2] 25 7a }

  condition:
    any of them
}