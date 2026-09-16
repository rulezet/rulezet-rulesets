rule TTP_XOR_WriteProcessMemory_ecd2 {
  strings:
    $key_ecd2 = { bb a0 [2] 89 82 [2] 8f b7 [2] a1 b7 [2] 9e ab }

  condition:
    any of them
}