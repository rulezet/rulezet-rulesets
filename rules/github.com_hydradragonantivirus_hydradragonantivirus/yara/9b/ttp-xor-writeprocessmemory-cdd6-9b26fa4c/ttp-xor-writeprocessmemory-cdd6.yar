rule TTP_XOR_WriteProcessMemory_cdd6 {
  strings:
    $key_cdd6 = { 9a a4 [2] a8 86 [2] ae b3 [2] 80 b3 [2] bf af }

  condition:
    any of them
}