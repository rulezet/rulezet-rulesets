rule TTP_XOR_WriteProcessMemory_18d3 {
  strings:
    $key_18d3 = { 4f a1 [2] 7d 83 [2] 7b b6 [2] 55 b6 [2] 6a aa }

  condition:
    any of them
}