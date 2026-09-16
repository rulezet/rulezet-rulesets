rule TTP_XOR_WriteProcessMemory_1cd1 {
  strings:
    $key_1cd1 = { 4b a3 [2] 79 81 [2] 7f b4 [2] 51 b4 [2] 6e a8 }

  condition:
    any of them
}