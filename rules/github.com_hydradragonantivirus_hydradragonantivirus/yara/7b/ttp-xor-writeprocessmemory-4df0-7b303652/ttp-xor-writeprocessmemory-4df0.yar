rule TTP_XOR_WriteProcessMemory_4df0 {
  strings:
    $key_4df0 = { 1a 82 [2] 28 a0 [2] 2e 95 [2] 00 95 [2] 3f 89 }

  condition:
    any of them
}