rule TTP_XOR_WriteProcessMemory_5563 {
  strings:
    $key_5563 = { 02 11 [2] 30 33 [2] 36 06 [2] 18 06 [2] 27 1a }

  condition:
    any of them
}