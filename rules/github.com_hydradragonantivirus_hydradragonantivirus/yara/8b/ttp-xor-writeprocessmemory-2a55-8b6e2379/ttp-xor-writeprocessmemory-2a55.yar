rule TTP_XOR_WriteProcessMemory_2a55 {
  strings:
    $key_2a55 = { 7d 27 [2] 4f 05 [2] 49 30 [2] 67 30 [2] 58 2c }

  condition:
    any of them
}