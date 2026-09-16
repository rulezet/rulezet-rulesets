rule TTP_XOR_MULT_DOSStub_d11a {
  strings:
    $key_d11a = { 85 72 [2] f1 6a [2] b6 68 [2] f1 79 [2] bf 75 [2] b3 7f [2] a4 74 [2] bf 3a [2] 82 }

  condition:
    any of them
}