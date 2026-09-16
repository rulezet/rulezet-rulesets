rule TTP_XOR_WriteProcessMemory_4da7 {
  strings:
    $key_4da7 = { 1a d5 [2] 28 f7 [2] 2e c2 [2] 00 c2 [2] 3f de }

  condition:
    any of them
}