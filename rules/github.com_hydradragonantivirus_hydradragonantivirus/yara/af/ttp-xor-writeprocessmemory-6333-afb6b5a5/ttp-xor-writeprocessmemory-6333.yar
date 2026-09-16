rule TTP_XOR_WriteProcessMemory_6333 {
  strings:
    $key_6333 = { 34 41 [2] 06 63 [2] 00 56 [2] 2e 56 [2] 11 4a }

  condition:
    any of them
}