rule TTP_XOR_WriteProcessMemory_75d1 {
  strings:
    $key_75d1 = { 22 a3 [2] 10 81 [2] 16 b4 [2] 38 b4 [2] 07 a8 }

  condition:
    any of them
}