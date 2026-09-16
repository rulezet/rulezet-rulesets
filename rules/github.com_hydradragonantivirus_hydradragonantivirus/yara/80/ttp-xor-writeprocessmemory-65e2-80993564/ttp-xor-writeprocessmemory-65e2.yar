rule TTP_XOR_WriteProcessMemory_65e2 {
  strings:
    $key_65e2 = { 32 90 [2] 00 b2 [2] 06 87 [2] 28 87 [2] 17 9b }

  condition:
    any of them
}