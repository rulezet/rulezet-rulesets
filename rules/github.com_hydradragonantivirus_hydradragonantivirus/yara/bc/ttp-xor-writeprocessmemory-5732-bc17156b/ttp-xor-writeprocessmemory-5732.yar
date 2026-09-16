rule TTP_XOR_WriteProcessMemory_5732 {
  strings:
    $key_5732 = { 00 40 [2] 32 62 [2] 34 57 [2] 1a 57 [2] 25 4b }

  condition:
    any of them
}