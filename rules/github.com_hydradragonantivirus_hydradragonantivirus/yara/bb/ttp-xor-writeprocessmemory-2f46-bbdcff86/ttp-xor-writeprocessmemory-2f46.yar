rule TTP_XOR_WriteProcessMemory_2f46 {
  strings:
    $key_2f46 = { 78 34 [2] 4a 16 [2] 4c 23 [2] 62 23 [2] 5d 3f }

  condition:
    any of them
}