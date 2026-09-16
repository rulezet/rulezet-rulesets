rule TTP_XOR_WriteProcessMemory_4de7 {
  strings:
    $key_4de7 = { 1a 95 [2] 28 b7 [2] 2e 82 [2] 00 82 [2] 3f 9e }

  condition:
    any of them
}