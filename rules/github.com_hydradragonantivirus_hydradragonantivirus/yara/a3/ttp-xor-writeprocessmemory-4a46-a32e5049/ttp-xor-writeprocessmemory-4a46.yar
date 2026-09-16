rule TTP_XOR_WriteProcessMemory_4a46 {
  strings:
    $key_4a46 = { 1d 34 [2] 2f 16 [2] 29 23 [2] 07 23 [2] 38 3f }

  condition:
    any of them
}