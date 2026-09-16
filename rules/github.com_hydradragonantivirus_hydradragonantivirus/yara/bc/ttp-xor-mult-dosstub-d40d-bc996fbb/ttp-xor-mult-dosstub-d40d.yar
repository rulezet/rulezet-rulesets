rule TTP_XOR_MULT_DOSStub_d40d {
  strings:
    $key_d40d = { 80 65 [2] f4 7d [2] b3 7f [2] f4 6e [2] ba 62 [2] b6 68 [2] a1 63 [2] ba 2d [2] 87 }

  condition:
    any of them
}