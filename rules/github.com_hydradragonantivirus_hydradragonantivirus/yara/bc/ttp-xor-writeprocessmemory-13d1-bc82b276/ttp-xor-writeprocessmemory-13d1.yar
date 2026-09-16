rule TTP_XOR_WriteProcessMemory_13d1 {
  strings:
    $key_13d1 = { 44 a3 [2] 76 81 [2] 70 b4 [2] 5e b4 [2] 61 a8 }

  condition:
    any of them
}