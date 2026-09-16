rule TTP_XOR_MULT_DOSStub_96de {
  strings:
    $key_96de = { c2 b6 [2] b6 ae [2] f1 ac [2] b6 bd [2] f8 b1 [2] f4 bb [2] e3 b0 [2] f8 fe [2] c5 }

  condition:
    any of them
}