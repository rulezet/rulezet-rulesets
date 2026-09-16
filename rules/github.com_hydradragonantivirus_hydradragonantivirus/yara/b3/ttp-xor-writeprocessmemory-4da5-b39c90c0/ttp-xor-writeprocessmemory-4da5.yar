rule TTP_XOR_WriteProcessMemory_4da5 {
  strings:
    $key_4da5 = { 1a d7 [2] 28 f5 [2] 2e c0 [2] 00 c0 [2] 3f dc }

  condition:
    any of them
}