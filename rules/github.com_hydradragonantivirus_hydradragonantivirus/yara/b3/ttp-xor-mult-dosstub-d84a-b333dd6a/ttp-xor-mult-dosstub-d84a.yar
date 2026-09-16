rule TTP_XOR_MULT_DOSStub_d84a {
  strings:
    $key_d84a = { 8c 22 [2] f8 3a [2] bf 38 [2] f8 29 [2] b6 25 [2] ba 2f [2] ad 24 [2] b6 6a [2] 8b }

  condition:
    any of them
}