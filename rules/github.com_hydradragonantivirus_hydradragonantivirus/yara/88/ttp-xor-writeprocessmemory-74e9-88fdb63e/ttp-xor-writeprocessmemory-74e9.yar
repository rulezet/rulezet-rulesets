rule TTP_XOR_WriteProcessMemory_74e9 {
  strings:
    $key_74e9 = { 23 9b [2] 11 b9 [2] 17 8c [2] 39 8c [2] 06 90 }

  condition:
    any of them
}