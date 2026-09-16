rule TTP_XOR_MULT_DOSStub_d45d {
  strings:
    $key_d45d = { 80 35 [2] f4 2d [2] b3 2f [2] f4 3e [2] ba 32 [2] b6 38 [2] a1 33 [2] ba 7d [2] 87 }

  condition:
    any of them
}