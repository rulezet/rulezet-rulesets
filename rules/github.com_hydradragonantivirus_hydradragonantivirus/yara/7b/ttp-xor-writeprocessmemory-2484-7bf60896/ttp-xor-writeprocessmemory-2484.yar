rule TTP_XOR_WriteProcessMemory_2484 {
  strings:
    $key_2484 = { 73 f6 [2] 41 d4 [2] 47 e1 [2] 69 e1 [2] 56 fd }

  condition:
    any of them
}