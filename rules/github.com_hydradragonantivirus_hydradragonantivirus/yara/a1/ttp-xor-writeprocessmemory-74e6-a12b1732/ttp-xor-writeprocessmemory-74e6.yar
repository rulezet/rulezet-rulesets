rule TTP_XOR_WriteProcessMemory_74e6 {
  strings:
    $key_74e6 = { 23 94 [2] 11 b6 [2] 17 83 [2] 39 83 [2] 06 9f }

  condition:
    any of them
}