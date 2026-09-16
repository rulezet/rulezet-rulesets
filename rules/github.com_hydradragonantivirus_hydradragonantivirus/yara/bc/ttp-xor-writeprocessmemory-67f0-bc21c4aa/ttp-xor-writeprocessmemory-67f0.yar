rule TTP_XOR_WriteProcessMemory_67f0 {
  strings:
    $key_67f0 = { 30 82 [2] 02 a0 [2] 04 95 [2] 2a 95 [2] 15 89 }

  condition:
    any of them
}