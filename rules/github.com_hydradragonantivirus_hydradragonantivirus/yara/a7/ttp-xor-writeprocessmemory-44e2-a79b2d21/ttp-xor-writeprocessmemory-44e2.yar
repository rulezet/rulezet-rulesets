rule TTP_XOR_WriteProcessMemory_44e2 {
  strings:
    $key_44e2 = { 13 90 [2] 21 b2 [2] 27 87 [2] 09 87 [2] 36 9b }

  condition:
    any of them
}