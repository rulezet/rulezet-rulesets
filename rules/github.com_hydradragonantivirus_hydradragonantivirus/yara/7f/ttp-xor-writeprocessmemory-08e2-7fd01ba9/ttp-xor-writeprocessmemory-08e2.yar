rule TTP_XOR_WriteProcessMemory_08e2 {
  strings:
    $key_08e2 = { 5f 90 [2] 6d b2 [2] 6b 87 [2] 45 87 [2] 7a 9b }

  condition:
    any of them
}