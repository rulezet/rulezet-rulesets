rule TTP_XOR_WriteProcessMemory_1d63 {
  strings:
    $key_1d63 = { 4a 11 [2] 78 33 [2] 7e 06 [2] 50 06 [2] 6f 1a }

  condition:
    any of them
}