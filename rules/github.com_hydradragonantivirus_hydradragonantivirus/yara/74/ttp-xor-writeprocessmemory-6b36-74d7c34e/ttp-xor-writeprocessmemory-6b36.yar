rule TTP_XOR_WriteProcessMemory_6b36 {
  strings:
    $key_6b36 = { 3c 44 [2] 0e 66 [2] 08 53 [2] 26 53 [2] 19 4f }

  condition:
    any of them
}