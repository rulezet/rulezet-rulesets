rule TTP_XOR_WriteProcessMemory_4da2 {
  strings:
    $key_4da2 = { 1a d0 [2] 28 f2 [2] 2e c7 [2] 00 c7 [2] 3f db }

  condition:
    any of them
}