rule TTP_XOR_MULT_DOSStub_d445 {
  strings:
    $key_d445 = { 80 2d [2] f4 35 [2] b3 37 [2] f4 26 [2] ba 2a [2] b6 20 [2] a1 2b [2] ba 65 [2] 87 }

  condition:
    any of them
}