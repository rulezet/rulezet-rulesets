rule TTP_XOR_MULT_DOSStub_d420 {
  strings:
    $key_d420 = { 80 48 [2] f4 50 [2] b3 52 [2] f4 43 [2] ba 4f [2] b6 45 [2] a1 4e [2] ba 00 [2] 87 }

  condition:
    any of them
}