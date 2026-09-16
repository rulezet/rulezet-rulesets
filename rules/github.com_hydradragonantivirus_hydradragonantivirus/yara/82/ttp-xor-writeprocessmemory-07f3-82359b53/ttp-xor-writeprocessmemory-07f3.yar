rule TTP_XOR_WriteProcessMemory_07f3 {
  strings:
    $key_07f3 = { 50 81 [2] 62 a3 [2] 64 96 [2] 4a 96 [2] 75 8a }

  condition:
    any of them
}