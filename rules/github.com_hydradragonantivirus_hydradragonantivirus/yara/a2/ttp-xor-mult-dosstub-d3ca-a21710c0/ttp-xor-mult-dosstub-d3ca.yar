rule TTP_XOR_MULT_DOSStub_d3ca {
  strings:
    $key_d3ca = { 87 a2 [2] f3 ba [2] b4 b8 [2] f3 a9 [2] bd a5 [2] b1 af [2] a6 a4 [2] bd ea [2] 80 }

  condition:
    any of them
}