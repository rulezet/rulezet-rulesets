rule TTP_XOR_WriteProcessMemory_cdd1 {
  strings:
    $key_cdd1 = { 9a a3 [2] a8 81 [2] ae b4 [2] 80 b4 [2] bf a8 }

  condition:
    any of them
}