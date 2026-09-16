rule TTP_XOR_MULT_DOSStub_d440 {
  strings:
    $key_d440 = { 80 28 [2] f4 30 [2] b3 32 [2] f4 23 [2] ba 2f [2] b6 25 [2] a1 2e [2] ba 60 [2] 87 }

  condition:
    any of them
}