rule TTP_XOR_WriteProcessMemory_74d4 {
  strings:
    $key_74d4 = { 23 a6 [2] 11 84 [2] 17 b1 [2] 39 b1 [2] 06 ad }

  condition:
    any of them
}