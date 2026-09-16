rule TTP_XOR_MULT_DOSStub_d43a {
  strings:
    $key_d43a = { 80 52 [2] f4 4a [2] b3 48 [2] f4 59 [2] ba 55 [2] b6 5f [2] a1 54 [2] ba 1a [2] 87 }

  condition:
    any of them
}