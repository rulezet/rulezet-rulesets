rule TTP_XOR_WriteProcessMemory_25e6 {
  strings:
    $key_25e6 = { 72 94 [2] 40 b6 [2] 46 83 [2] 68 83 [2] 57 9f }

  condition:
    any of them
}