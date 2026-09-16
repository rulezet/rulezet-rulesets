rule TTP_XOR_WriteProcessMemory_2d46 {
  strings:
    $key_2d46 = { 7a 34 [2] 48 16 [2] 4e 23 [2] 60 23 [2] 5f 3f }

  condition:
    any of them
}