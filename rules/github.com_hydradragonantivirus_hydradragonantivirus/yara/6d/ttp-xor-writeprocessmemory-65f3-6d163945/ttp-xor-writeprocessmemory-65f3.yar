rule TTP_XOR_WriteProcessMemory_65f3 {
  strings:
    $key_65f3 = { 32 81 [2] 00 a3 [2] 06 96 [2] 28 96 [2] 17 8a }

  condition:
    any of them
}