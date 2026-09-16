rule TTP_XOR_WriteProcessMemory_4d72 {
  strings:
    $key_4d72 = { 1a 00 [2] 28 22 [2] 2e 17 [2] 00 17 [2] 3f 0b }

  condition:
    any of them
}