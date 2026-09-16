rule TTP_XOR_WriteProcessMemory_75f0 {
  strings:
    $key_75f0 = { 22 82 [2] 10 a0 [2] 16 95 [2] 38 95 [2] 07 89 }

  condition:
    any of them
}