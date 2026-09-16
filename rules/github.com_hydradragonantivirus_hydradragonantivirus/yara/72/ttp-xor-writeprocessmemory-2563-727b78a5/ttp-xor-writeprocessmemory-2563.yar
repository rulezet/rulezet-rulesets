rule TTP_XOR_WriteProcessMemory_2563 {
  strings:
    $key_2563 = { 72 11 [2] 40 33 [2] 46 06 [2] 68 06 [2] 57 1a }

  condition:
    any of them
}