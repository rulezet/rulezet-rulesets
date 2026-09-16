rule TTP_XOR_WriteProcessMemory_4d73 {
  strings:
    $key_4d73 = { 1a 01 [2] 28 23 [2] 2e 16 [2] 00 16 [2] 3f 0a }

  condition:
    any of them
}