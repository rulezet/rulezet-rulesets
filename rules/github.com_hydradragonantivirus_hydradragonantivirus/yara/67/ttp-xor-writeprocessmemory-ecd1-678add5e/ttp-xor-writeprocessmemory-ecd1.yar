rule TTP_XOR_WriteProcessMemory_ecd1 {
  strings:
    $key_ecd1 = { bb a3 [2] 89 81 [2] 8f b4 [2] a1 b4 [2] 9e a8 }

  condition:
    any of them
}