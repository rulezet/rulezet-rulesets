rule TTP_XOR_WriteProcessMemory_0763 {
  strings:
    $key_0763 = { 50 11 [2] 62 33 [2] 64 06 [2] 4a 06 [2] 75 1a }

  condition:
    any of them
}