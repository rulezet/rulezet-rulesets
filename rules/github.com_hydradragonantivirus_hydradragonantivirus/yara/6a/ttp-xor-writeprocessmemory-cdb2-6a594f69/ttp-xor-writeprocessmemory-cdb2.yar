rule TTP_XOR_WriteProcessMemory_cdb2 {
  strings:
    $key_cdb2 = { 9a c0 [2] a8 e2 [2] ae d7 [2] 80 d7 [2] bf cb }

  condition:
    any of them
}