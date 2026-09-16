rule TTP_XOR_WriteProcessMemory_4d22 {
  strings:
    $key_4d22 = { 1a 50 [2] 28 72 [2] 2e 47 [2] 00 47 [2] 3f 5b }

  condition:
    any of them
}