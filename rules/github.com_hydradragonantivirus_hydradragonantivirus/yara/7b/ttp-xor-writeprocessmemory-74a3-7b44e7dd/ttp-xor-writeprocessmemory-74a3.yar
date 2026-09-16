rule TTP_XOR_WriteProcessMemory_74a3 {
  strings:
    $key_74a3 = { 23 d1 [2] 11 f3 [2] 17 c6 [2] 39 c6 [2] 06 da }

  condition:
    any of them
}