rule TTP_XOR_WriteProcessMemory_48d3 {
  strings:
    $key_48d3 = { 1f a1 [2] 2d 83 [2] 2b b6 [2] 05 b6 [2] 3a aa }

  condition:
    any of them
}