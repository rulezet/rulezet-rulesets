rule TTP_XOR_WriteProcessMemory_18e2 {
  strings:
    $key_18e2 = { 4f 90 [2] 7d b2 [2] 7b 87 [2] 55 87 [2] 6a 9b }

  condition:
    any of them
}