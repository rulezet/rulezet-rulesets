rule TTP_XOR_WriteProcessMemory_25f3 {
  strings:
    $key_25f3 = { 72 81 [2] 40 a3 [2] 46 96 [2] 68 96 [2] 57 8a }

  condition:
    any of them
}