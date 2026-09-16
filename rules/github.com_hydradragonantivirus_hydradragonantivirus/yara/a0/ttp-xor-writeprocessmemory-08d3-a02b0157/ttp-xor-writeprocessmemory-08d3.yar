rule TTP_XOR_WriteProcessMemory_08d3 {
  strings:
    $key_08d3 = { 5f a1 [2] 6d 83 [2] 6b b6 [2] 45 b6 [2] 7a aa }

  condition:
    any of them
}