rule TTP_XOR_WriteProcessMemory_6cd1 {
  strings:
    $key_6cd1 = { 3b a3 [2] 09 81 [2] 0f b4 [2] 21 b4 [2] 1e a8 }

  condition:
    any of them
}