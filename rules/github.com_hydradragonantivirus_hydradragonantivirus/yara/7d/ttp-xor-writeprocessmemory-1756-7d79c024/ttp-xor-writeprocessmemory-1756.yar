rule TTP_XOR_WriteProcessMemory_1756 {
  strings:
    $key_1756 = { 40 24 [2] 72 06 [2] 74 33 [2] 5a 33 [2] 65 2f }

  condition:
    any of them
}