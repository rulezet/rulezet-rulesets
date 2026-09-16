rule TTP_XOR_WriteProcessMemory_5733 {
  strings:
    $key_5733 = { 00 41 [2] 32 63 [2] 34 56 [2] 1a 56 [2] 25 4a }

  condition:
    any of them
}