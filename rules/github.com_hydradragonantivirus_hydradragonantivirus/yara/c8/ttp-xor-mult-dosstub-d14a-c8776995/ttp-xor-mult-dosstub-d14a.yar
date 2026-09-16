rule TTP_XOR_MULT_DOSStub_d14a {
  strings:
    $key_d14a = { 85 22 [2] f1 3a [2] b6 38 [2] f1 29 [2] bf 25 [2] b3 2f [2] a4 24 [2] bf 6a [2] 82 }

  condition:
    any of them
}