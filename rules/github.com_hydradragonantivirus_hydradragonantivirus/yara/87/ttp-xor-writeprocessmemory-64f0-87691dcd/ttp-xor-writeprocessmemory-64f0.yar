rule TTP_XOR_WriteProcessMemory_64f0 {
  strings:
    $key_64f0 = { 33 82 [2] 01 a0 [2] 07 95 [2] 29 95 [2] 16 89 }

  condition:
    any of them
}