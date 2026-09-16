rule TTP_XOR_MULT_DOSStub_d13a {
  strings:
    $key_d13a = { 85 52 [2] f1 4a [2] b6 48 [2] f1 59 [2] bf 55 [2] b3 5f [2] a4 54 [2] bf 1a [2] 82 }

  condition:
    any of them
}