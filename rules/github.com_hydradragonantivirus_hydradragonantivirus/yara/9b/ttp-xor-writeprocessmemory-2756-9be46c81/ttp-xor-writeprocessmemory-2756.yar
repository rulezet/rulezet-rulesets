rule TTP_XOR_WriteProcessMemory_2756 {
  strings:
    $key_2756 = { 70 24 [2] 42 06 [2] 44 33 [2] 6a 33 [2] 55 2f }

  condition:
    any of them
}