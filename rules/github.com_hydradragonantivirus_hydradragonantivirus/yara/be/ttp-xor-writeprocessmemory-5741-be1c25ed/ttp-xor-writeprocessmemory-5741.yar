rule TTP_XOR_WriteProcessMemory_5741 {
  strings:
    $key_5741 = { 00 33 [2] 32 11 [2] 34 24 [2] 1a 24 [2] 25 38 }

  condition:
    any of them
}