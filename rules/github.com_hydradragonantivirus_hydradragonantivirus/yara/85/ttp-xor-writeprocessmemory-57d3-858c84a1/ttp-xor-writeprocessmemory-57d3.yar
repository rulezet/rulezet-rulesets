rule TTP_XOR_WriteProcessMemory_57d3 {
  strings:
    $key_57d3 = { 00 a1 [2] 32 83 [2] 34 b6 [2] 1a b6 [2] 25 aa }

  condition:
    any of them
}