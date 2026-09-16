rule TTP_XOR_WriteProcessMemory_74f0 {
  strings:
    $key_74f0 = { 23 82 [2] 11 a0 [2] 17 95 [2] 39 95 [2] 06 89 }

  condition:
    any of them
}