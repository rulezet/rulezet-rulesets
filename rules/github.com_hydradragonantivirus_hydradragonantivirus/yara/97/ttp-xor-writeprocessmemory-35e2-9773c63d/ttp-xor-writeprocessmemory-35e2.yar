rule TTP_XOR_WriteProcessMemory_35e2 {
  strings:
    $key_35e2 = { 62 90 [2] 50 b2 [2] 56 87 [2] 78 87 [2] 47 9b }

  condition:
    any of them
}