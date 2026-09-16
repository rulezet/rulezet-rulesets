rule TTP_XOR_WriteProcessMemory_2b36 {
  strings:
    $key_2b36 = { 7c 44 [2] 4e 66 [2] 48 53 [2] 66 53 [2] 59 4f }

  condition:
    any of them
}