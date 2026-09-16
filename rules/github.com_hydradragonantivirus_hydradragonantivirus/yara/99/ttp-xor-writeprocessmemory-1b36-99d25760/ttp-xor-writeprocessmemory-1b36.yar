rule TTP_XOR_WriteProcessMemory_1b36 {
  strings:
    $key_1b36 = { 4c 44 [2] 7e 66 [2] 78 53 [2] 56 53 [2] 69 4f }

  condition:
    any of them
}