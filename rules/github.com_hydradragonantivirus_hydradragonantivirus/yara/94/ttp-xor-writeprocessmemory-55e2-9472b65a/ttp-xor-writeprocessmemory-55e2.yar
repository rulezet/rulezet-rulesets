rule TTP_XOR_WriteProcessMemory_55e2 {
  strings:
    $key_55e2 = { 02 90 [2] 30 b2 [2] 36 87 [2] 18 87 [2] 27 9b }

  condition:
    any of them
}