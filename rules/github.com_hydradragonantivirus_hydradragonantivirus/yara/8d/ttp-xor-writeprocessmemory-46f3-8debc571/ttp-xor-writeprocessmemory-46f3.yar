rule TTP_XOR_WriteProcessMemory_46f3 {
  strings:
    $key_46f3 = { 11 81 [2] 23 a3 [2] 25 96 [2] 0b 96 [2] 34 8a }

  condition:
    any of them
}