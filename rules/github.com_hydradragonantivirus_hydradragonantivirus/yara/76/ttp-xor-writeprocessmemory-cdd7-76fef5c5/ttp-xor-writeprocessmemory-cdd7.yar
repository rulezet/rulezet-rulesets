rule TTP_XOR_WriteProcessMemory_cdd7 {
  strings:
    $key_cdd7 = { 9a a5 [2] a8 87 [2] ae b2 [2] 80 b2 [2] bf ae }

  condition:
    any of them
}