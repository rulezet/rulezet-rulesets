rule TTP_XOR_MULT_DOSStub_d476 {
  strings:
    $key_d476 = { 80 1e [2] f4 06 [2] b3 04 [2] f4 15 [2] ba 19 [2] b6 13 [2] a1 18 [2] ba 56 [2] 87 }

  condition:
    any of them
}