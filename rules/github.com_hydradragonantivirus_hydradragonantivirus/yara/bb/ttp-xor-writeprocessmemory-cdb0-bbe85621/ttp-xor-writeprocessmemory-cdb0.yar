rule TTP_XOR_WriteProcessMemory_cdb0 {
  strings:
    $key_cdb0 = { 9a c2 [2] a8 e0 [2] ae d5 [2] 80 d5 [2] bf c9 }

  condition:
    any of them
}