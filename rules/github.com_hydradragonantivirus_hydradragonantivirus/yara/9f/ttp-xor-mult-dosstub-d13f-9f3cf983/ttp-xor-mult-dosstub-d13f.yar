rule TTP_XOR_MULT_DOSStub_d13f {
  strings:
    $key_d13f = { 85 57 [2] f1 4f [2] b6 4d [2] f1 5c [2] bf 50 [2] b3 5a [2] a4 51 [2] bf 1f [2] 82 }

  condition:
    any of them
}