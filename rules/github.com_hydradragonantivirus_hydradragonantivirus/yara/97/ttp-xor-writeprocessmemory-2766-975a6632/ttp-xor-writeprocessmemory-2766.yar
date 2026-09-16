rule TTP_XOR_WriteProcessMemory_2766 {
  strings:
    $key_2766 = { 70 14 [2] 42 36 [2] 44 03 [2] 6a 03 [2] 55 1f }

  condition:
    any of them
}