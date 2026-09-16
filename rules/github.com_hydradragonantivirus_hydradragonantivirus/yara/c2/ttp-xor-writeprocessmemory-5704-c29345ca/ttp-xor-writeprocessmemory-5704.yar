rule TTP_XOR_WriteProcessMemory_5704 {
  strings:
    $key_5704 = { 00 76 [2] 32 54 [2] 34 61 [2] 1a 61 [2] 25 7d }

  condition:
    any of them
}