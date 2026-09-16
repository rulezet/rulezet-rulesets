rule TTP_XOR_WriteProcessMemory_77a3 {
  strings:
    $key_77a3 = { 20 d1 [2] 12 f3 [2] 14 c6 [2] 3a c6 [2] 05 da }

  condition:
    any of them
}