rule TTP_XOR_WriteProcessMemory_1ed1 {
  strings:
    $key_1ed1 = { 49 a3 [2] 7b 81 [2] 7d b4 [2] 53 b4 [2] 6c a8 }

  condition:
    any of them
}