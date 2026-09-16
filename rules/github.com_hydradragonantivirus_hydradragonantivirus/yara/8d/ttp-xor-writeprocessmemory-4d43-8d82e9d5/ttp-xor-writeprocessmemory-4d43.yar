rule TTP_XOR_WriteProcessMemory_4d43 {
  strings:
    $key_4d43 = { 1a 31 [2] 28 13 [2] 2e 26 [2] 00 26 [2] 3f 3a }

  condition:
    any of them
}