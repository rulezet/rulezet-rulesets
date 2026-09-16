rule TTP_XOR_MULT_DOSStub_d44d {
  strings:
    $key_d44d = { 80 25 [2] f4 3d [2] b3 3f [2] f4 2e [2] ba 22 [2] b6 28 [2] a1 23 [2] ba 6d [2] 87 }

  condition:
    any of them
}