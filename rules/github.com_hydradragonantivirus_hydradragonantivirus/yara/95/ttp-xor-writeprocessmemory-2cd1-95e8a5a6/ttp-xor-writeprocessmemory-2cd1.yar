rule TTP_XOR_WriteProcessMemory_2cd1 {
  strings:
    $key_2cd1 = { 7b a3 [2] 49 81 [2] 4f b4 [2] 61 b4 [2] 5e a8 }

  condition:
    any of them
}