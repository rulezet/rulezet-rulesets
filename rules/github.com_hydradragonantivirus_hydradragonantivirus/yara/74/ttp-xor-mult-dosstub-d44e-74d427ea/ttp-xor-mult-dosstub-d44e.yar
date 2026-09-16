rule TTP_XOR_MULT_DOSStub_d44e {
  strings:
    $key_d44e = { 80 26 [2] f4 3e [2] b3 3c [2] f4 2d [2] ba 21 [2] b6 2b [2] a1 20 [2] ba 6e [2] 87 }

  condition:
    any of them
}