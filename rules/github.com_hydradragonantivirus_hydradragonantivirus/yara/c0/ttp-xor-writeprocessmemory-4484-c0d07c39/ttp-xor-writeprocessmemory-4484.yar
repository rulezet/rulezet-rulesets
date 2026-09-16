rule TTP_XOR_WriteProcessMemory_4484 {
  strings:
    $key_4484 = { 13 f6 [2] 21 d4 [2] 27 e1 [2] 09 e1 [2] 36 fd }

  condition:
    any of them
}