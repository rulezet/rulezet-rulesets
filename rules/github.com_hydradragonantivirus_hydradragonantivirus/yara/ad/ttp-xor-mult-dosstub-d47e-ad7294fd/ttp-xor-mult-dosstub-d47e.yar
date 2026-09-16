rule TTP_XOR_MULT_DOSStub_d47e {
  strings:
    $key_d47e = { 80 16 [2] f4 0e [2] b3 0c [2] f4 1d [2] ba 11 [2] b6 1b [2] a1 10 [2] ba 5e [2] 87 }

  condition:
    any of them
}