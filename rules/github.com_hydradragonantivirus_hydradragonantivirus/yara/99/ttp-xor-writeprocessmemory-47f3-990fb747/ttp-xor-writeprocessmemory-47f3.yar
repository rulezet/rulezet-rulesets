rule TTP_XOR_WriteProcessMemory_47f3 {
  strings:
    $key_47f3 = { 10 81 [2] 22 a3 [2] 24 96 [2] 0a 96 [2] 35 8a }

  condition:
    any of them
}