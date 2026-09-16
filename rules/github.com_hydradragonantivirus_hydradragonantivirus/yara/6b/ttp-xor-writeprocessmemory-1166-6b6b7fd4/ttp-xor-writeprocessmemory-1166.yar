rule TTP_XOR_WriteProcessMemory_1166 {
  strings:
    $key_1166 = { 46 14 [2] 74 36 [2] 72 03 [2] 5c 03 [2] 63 1f }

  condition:
    any of them
}