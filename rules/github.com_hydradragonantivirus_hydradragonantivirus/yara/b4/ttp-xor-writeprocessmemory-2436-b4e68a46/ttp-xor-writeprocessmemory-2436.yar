rule TTP_XOR_WriteProcessMemory_2436 {
  strings:
    $key_2436 = { 73 44 [2] 41 66 [2] 47 53 [2] 69 53 [2] 56 4f }

  condition:
    any of them
}