rule TTP_XOR_WriteProcessMemory_c463 {
  strings:
    $key_c463 = { 93 11 [2] a1 33 [2] a7 06 [2] 89 06 [2] b6 1a }

  condition:
    any of them
}