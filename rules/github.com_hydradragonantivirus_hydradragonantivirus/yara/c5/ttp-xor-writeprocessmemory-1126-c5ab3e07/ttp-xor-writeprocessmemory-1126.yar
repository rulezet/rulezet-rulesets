rule TTP_XOR_WriteProcessMemory_1126 {
  strings:
    $key_1126 = { 46 54 [2] 74 76 [2] 72 43 [2] 5c 43 [2] 63 5f }

  condition:
    any of them
}