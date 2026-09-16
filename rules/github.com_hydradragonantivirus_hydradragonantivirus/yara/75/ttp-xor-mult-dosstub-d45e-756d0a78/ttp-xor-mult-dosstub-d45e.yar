rule TTP_XOR_MULT_DOSStub_d45e {
  strings:
    $key_d45e = { 80 36 [2] f4 2e [2] b3 2c [2] f4 3d [2] ba 31 [2] b6 3b [2] a1 30 [2] ba 7e [2] 87 }

  condition:
    any of them
}