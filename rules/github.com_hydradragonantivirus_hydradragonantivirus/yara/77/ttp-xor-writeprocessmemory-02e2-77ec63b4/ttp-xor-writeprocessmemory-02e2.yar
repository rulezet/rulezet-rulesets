rule TTP_XOR_WriteProcessMemory_02e2 {
  strings:
    $key_02e2 = { 55 90 [2] 67 b2 [2] 61 87 [2] 4f 87 [2] 70 9b }

  condition:
    any of them
}