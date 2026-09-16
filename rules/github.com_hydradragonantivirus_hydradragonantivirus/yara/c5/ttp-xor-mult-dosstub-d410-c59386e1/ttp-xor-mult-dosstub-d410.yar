rule TTP_XOR_MULT_DOSStub_d410 {
  strings:
    $key_d410 = { 80 78 [2] f4 60 [2] b3 62 [2] f4 73 [2] ba 7f [2] b6 75 [2] a1 7e [2] ba 30 [2] 87 }

  condition:
    any of them
}