rule TTP_XOR_WriteProcessMemory_67f3 {
  strings:
    $key_67f3 = { 30 81 [2] 02 a3 [2] 04 96 [2] 2a 96 [2] 15 8a }

  condition:
    any of them
}