rule TTP_XOR_WriteProcessMemory_74f6 {
  strings:
    $key_74f6 = { 23 84 [2] 11 a6 [2] 17 93 [2] 39 93 [2] 06 8f }

  condition:
    any of them
}