rule TTP_XOR_WriteProcessMemory_13e2 {
  strings:
    $key_13e2 = { 44 90 [2] 76 b2 [2] 70 87 [2] 5e 87 [2] 61 9b }

  condition:
    any of them
}