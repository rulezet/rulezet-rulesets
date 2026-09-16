rule TTP_XOR_WriteProcessMemory_3b36 {
  strings:
    $key_3b36 = { 6c 44 [2] 5e 66 [2] 58 53 [2] 76 53 [2] 49 4f }

  condition:
    any of them
}