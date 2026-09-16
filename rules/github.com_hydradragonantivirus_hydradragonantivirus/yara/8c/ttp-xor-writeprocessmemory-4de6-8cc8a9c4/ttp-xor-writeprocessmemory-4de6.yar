rule TTP_XOR_WriteProcessMemory_4de6 {
  strings:
    $key_4de6 = { 1a 94 [2] 28 b6 [2] 2e 83 [2] 00 83 [2] 3f 9f }

  condition:
    any of them
}