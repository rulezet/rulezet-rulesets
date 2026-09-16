rule TTP_XOR_WriteProcessMemory_07e2 {
  strings:
    $key_07e2 = { 50 90 [2] 62 b2 [2] 64 87 [2] 4a 87 [2] 75 9b }

  condition:
    any of them
}