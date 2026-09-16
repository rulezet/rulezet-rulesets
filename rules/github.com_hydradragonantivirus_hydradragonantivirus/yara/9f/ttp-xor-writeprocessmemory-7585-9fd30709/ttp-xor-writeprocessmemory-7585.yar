rule TTP_XOR_WriteProcessMemory_7585 {
  strings:
    $key_7585 = { 22 f7 [2] 10 d5 [2] 16 e0 [2] 38 e0 [2] 07 fc }

  condition:
    any of them
}