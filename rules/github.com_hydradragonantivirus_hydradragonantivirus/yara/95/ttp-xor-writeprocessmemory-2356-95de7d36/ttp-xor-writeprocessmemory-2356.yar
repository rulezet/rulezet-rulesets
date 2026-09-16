rule TTP_XOR_WriteProcessMemory_2356 {
  strings:
    $key_2356 = { 74 24 [2] 46 06 [2] 40 33 [2] 6e 33 [2] 51 2f }

  condition:
    any of them
}