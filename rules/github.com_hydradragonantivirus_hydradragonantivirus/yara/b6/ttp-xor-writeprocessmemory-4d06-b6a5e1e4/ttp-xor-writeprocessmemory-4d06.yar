rule TTP_XOR_WriteProcessMemory_4d06 {
  strings:
    $key_4d06 = { 1a 74 [2] 28 56 [2] 2e 63 [2] 00 63 [2] 3f 7f }

  condition:
    any of them
}