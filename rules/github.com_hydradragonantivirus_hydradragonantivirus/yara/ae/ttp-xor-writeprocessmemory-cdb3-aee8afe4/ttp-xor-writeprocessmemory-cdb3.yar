rule TTP_XOR_WriteProcessMemory_cdb3 {
  strings:
    $key_cdb3 = { 9a c1 [2] a8 e3 [2] ae d6 [2] 80 d6 [2] bf ca }

  condition:
    any of them
}