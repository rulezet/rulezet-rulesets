rule TTP_XOR_WriteProcessMemory_cdb5 {
  strings:
    $key_cdb5 = { 9a c7 [2] a8 e5 [2] ae d0 [2] 80 d0 [2] bf cc }

  condition:
    any of them
}