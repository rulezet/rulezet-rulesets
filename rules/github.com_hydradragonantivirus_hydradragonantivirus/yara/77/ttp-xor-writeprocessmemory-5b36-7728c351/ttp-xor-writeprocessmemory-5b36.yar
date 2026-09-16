rule TTP_XOR_WriteProcessMemory_5b36 {
  strings:
    $key_5b36 = { 0c 44 [2] 3e 66 [2] 38 53 [2] 16 53 [2] 29 4f }

  condition:
    any of them
}