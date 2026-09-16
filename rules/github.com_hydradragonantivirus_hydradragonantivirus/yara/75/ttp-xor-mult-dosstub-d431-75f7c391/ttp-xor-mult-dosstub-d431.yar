rule TTP_XOR_MULT_DOSStub_d431 {
  strings:
    $key_d431 = { 80 59 [2] f4 41 [2] b3 43 [2] f4 52 [2] ba 5e [2] b6 54 [2] a1 5f [2] ba 11 [2] 87 }

  condition:
    any of them
}