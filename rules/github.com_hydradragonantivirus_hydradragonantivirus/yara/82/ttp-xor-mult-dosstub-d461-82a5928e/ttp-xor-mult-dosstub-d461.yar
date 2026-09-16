rule TTP_XOR_MULT_DOSStub_d461 {
  strings:
    $key_d461 = { 80 09 [2] f4 11 [2] b3 13 [2] f4 02 [2] ba 0e [2] b6 04 [2] a1 0f [2] ba 41 [2] 87 }

  condition:
    any of them
}