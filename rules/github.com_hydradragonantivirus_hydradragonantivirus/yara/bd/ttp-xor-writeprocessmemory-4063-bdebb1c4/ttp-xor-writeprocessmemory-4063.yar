rule TTP_XOR_WriteProcessMemory_4063 {
  strings:
    $key_4063 = { 17 11 [2] 25 33 [2] 23 06 [2] 0d 06 [2] 32 1a }

  condition:
    any of them
}