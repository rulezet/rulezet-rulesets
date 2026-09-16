rule TTP_XOR_WriteProcessMemory_4366 {
  strings:
    $key_4366 = { 14 14 [2] 26 36 [2] 20 03 [2] 0e 03 [2] 31 1f }

  condition:
    any of them
}