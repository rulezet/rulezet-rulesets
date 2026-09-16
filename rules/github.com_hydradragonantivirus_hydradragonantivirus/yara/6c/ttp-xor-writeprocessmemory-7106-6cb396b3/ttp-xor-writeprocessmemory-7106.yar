rule TTP_XOR_WriteProcessMemory_7106 {
  strings:
    $key_7106 = { 26 74 [2] 14 56 [2] 12 63 [2] 3c 63 [2] 03 7f }

  condition:
    any of them
}