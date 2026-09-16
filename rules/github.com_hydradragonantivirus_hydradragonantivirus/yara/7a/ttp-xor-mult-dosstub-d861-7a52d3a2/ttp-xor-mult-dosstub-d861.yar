rule TTP_XOR_MULT_DOSStub_d861 {
  strings:
    $key_d861 = { 8c 09 [2] f8 11 [2] bf 13 [2] f8 02 [2] b6 0e [2] ba 04 [2] ad 0f [2] b6 41 [2] 8b }

  condition:
    any of them
}