rule TTP_XOR_WriteProcessMemory_1345 {
  strings:
    $key_1345 = { 44 37 [2] 76 15 [2] 70 20 [2] 5e 20 [2] 61 3c }

  condition:
    any of them
}