rule TTP_XOR_WriteProcessMemory_2e96 {
  strings:
    $key_2e96 = { 79 e4 [2] 4b c6 [2] 4d f3 [2] 63 f3 [2] 5c ef }

  condition:
    any of them
}