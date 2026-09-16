rule TTP_XOR_WriteProcessMemory_fbd6 {
  strings:
    $key_fbd6 = { ac a4 [2] 9e 86 [2] 98 b3 [2] b6 b3 [2] 89 af }

  condition:
    any of them
}