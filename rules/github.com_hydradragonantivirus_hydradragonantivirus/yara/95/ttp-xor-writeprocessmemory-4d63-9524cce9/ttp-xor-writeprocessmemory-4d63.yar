rule TTP_XOR_WriteProcessMemory_4d63 {
  strings:
    $key_4d63 = { 1a 11 [2] 28 33 [2] 2e 06 [2] 00 06 [2] 3f 1a }

  condition:
    any of them
}