rule TTP_XOR_MULT_DOSStub_d15a {
  strings:
    $key_d15a = { 85 32 [2] f1 2a [2] b6 28 [2] f1 39 [2] bf 35 [2] b3 3f [2] a4 34 [2] bf 7a [2] 82 }

  condition:
    any of them
}