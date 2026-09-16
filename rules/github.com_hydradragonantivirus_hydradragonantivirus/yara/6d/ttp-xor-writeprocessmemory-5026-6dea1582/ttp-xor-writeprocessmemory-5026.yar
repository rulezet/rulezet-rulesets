rule TTP_XOR_WriteProcessMemory_5026 {
  strings:
    $key_5026 = { 07 54 [2] 35 76 [2] 33 43 [2] 1d 43 [2] 22 5f }

  condition:
    any of them
}