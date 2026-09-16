rule TTP_XOR_WriteProcessMemory_74e4 {
  strings:
    $key_74e4 = { 23 96 [2] 11 b4 [2] 17 81 [2] 39 81 [2] 06 9d }

  condition:
    any of them
}