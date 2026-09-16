rule TTP_XOR_WriteProcessMemory_5484 {
  strings:
    $key_5484 = { 03 f6 [2] 31 d4 [2] 37 e1 [2] 19 e1 [2] 26 fd }

  condition:
    any of them
}