rule TTP_XOR_WriteProcessMemory_4d02 {
  strings:
    $key_4d02 = { 1a 70 [2] 28 52 [2] 2e 67 [2] 00 67 [2] 3f 7b }

  condition:
    any of them
}