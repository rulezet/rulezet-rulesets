rule TTP_XOR_WriteProcessMemory_2712 {
  strings:
    $key_2712 = { 70 60 [2] 42 42 [2] 44 77 [2] 6a 77 [2] 55 6b }

  condition:
    any of them
}