rule TTP_XOR_WriteProcessMemory_6732 {
  strings:
    $key_6732 = { 30 40 [2] 02 62 [2] 04 57 [2] 2a 57 [2] 15 4b }

  condition:
    any of them
}