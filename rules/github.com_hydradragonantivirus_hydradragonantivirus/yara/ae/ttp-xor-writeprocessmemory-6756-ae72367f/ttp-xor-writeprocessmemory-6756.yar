rule TTP_XOR_WriteProcessMemory_6756 {
  strings:
    $key_6756 = { 30 24 [2] 02 06 [2] 04 33 [2] 2a 33 [2] 15 2f }

  condition:
    any of them
}