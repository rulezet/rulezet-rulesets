rule TTP_XOR_WriteProcessMemory_76e2 {
  strings:
    $key_76e2 = { 21 90 [2] 13 b2 [2] 15 87 [2] 3b 87 [2] 04 9b }

  condition:
    any of them
}