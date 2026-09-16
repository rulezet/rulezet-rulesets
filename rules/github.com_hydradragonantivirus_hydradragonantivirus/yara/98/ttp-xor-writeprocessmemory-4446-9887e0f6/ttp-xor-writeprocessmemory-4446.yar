rule TTP_XOR_WriteProcessMemory_4446 {
  strings:
    $key_4446 = { 13 34 [2] 21 16 [2] 27 23 [2] 09 23 [2] 36 3f }

  condition:
    any of them
}