rule TTP_XOR_WriteProcessMemory_74f3 {
  strings:
    $key_74f3 = { 23 81 [2] 11 a3 [2] 17 96 [2] 39 96 [2] 06 8a }

  condition:
    any of them
}