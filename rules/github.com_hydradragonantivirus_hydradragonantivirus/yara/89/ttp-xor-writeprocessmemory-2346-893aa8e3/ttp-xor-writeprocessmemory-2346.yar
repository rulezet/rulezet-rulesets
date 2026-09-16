rule TTP_XOR_WriteProcessMemory_2346 {
  strings:
    $key_2346 = { 74 34 [2] 46 16 [2] 40 23 [2] 6e 23 [2] 51 3f }

  condition:
    any of them
}