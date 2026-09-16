rule TTP_XOR_MULT_DOSStub_d856 {
  strings:
    $key_d856 = { 8c 3e [2] f8 26 [2] bf 24 [2] f8 35 [2] b6 39 [2] ba 33 [2] ad 38 [2] b6 76 [2] 8b }

  condition:
    any of them
}