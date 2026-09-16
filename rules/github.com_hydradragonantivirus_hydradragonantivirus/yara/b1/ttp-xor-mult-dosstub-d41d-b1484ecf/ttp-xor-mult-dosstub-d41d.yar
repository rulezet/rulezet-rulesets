rule TTP_XOR_MULT_DOSStub_d41d {
  strings:
    $key_d41d = { 80 75 [2] f4 6d [2] b3 6f [2] f4 7e [2] ba 72 [2] b6 78 [2] a1 73 [2] ba 3d [2] 87 }

  condition:
    any of them
}