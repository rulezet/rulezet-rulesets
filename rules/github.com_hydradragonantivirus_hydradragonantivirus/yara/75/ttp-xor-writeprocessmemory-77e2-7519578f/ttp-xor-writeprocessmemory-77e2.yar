rule TTP_XOR_WriteProcessMemory_77e2 {
  strings:
    $key_77e2 = { 20 90 [2] 12 b2 [2] 14 87 [2] 3a 87 [2] 05 9b }

  condition:
    any of them
}