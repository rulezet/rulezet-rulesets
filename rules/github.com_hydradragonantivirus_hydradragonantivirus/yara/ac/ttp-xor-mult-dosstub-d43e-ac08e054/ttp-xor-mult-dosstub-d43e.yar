rule TTP_XOR_MULT_DOSStub_d43e {
  strings:
    $key_d43e = { 80 56 [2] f4 4e [2] b3 4c [2] f4 5d [2] ba 51 [2] b6 5b [2] a1 50 [2] ba 1e [2] 87 }

  condition:
    any of them
}