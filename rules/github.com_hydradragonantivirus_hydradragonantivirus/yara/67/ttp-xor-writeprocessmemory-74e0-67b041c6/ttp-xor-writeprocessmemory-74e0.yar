rule TTP_XOR_WriteProcessMemory_74e0 {
  strings:
    $key_74e0 = { 23 92 [2] 11 b0 [2] 17 85 [2] 39 85 [2] 06 99 }

  condition:
    any of them
}