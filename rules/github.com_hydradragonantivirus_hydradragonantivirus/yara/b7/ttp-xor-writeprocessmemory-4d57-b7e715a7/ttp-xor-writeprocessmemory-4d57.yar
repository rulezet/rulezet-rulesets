rule TTP_XOR_WriteProcessMemory_4d57 {
  strings:
    $key_4d57 = { 1a 25 [2] 28 07 [2] 2e 32 [2] 00 32 [2] 3f 2e }

  condition:
    any of them
}