rule TTP_XOR_WriteProcessMemory_17f3 {
  strings:
    $key_17f3 = { 40 81 [2] 72 a3 [2] 74 96 [2] 5a 96 [2] 65 8a }

  condition:
    any of them
}