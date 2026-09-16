rule TTP_XOR_WriteProcessMemory_5dd6 {
  strings:
    $key_5dd6 = { 0a a4 [2] 38 86 [2] 3e b3 [2] 10 b3 [2] 2f af }

  condition:
    any of them
}