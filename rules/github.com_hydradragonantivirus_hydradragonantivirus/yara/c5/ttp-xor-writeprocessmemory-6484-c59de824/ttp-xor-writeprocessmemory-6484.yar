rule TTP_XOR_WriteProcessMemory_6484 {
  strings:
    $key_6484 = { 33 f6 [2] 01 d4 [2] 07 e1 [2] 29 e1 [2] 16 fd }

  condition:
    any of them
}