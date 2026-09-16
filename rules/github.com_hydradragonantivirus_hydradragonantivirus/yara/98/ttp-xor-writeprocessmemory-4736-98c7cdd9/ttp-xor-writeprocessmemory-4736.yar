rule TTP_XOR_WriteProcessMemory_4736 {
  strings:
    $key_4736 = { 10 44 [2] 22 66 [2] 24 53 [2] 0a 53 [2] 35 4f }

  condition:
    any of them
}