rule TTP_XOR_WriteProcessMemory_1e96 {
  strings:
    $key_1e96 = { 49 e4 [2] 7b c6 [2] 7d f3 [2] 53 f3 [2] 6c ef }

  condition:
    any of them
}