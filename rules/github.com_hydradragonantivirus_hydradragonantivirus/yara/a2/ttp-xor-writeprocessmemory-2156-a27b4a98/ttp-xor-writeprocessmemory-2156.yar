rule TTP_XOR_WriteProcessMemory_2156 {
  strings:
    $key_2156 = { 76 24 [2] 44 06 [2] 42 33 [2] 6c 33 [2] 53 2f }

  condition:
    any of them
}