rule TTP_XOR_WriteProcessMemory_74c4 {
  strings:
    $key_74c4 = { 23 b6 [2] 11 94 [2] 17 a1 [2] 39 a1 [2] 06 bd }

  condition:
    any of them
}