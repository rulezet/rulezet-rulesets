rule TTP_XOR_MULT_DOSStub_d10a {
  strings:
    $key_d10a = { 85 62 [2] f1 7a [2] b6 78 [2] f1 69 [2] bf 65 [2] b3 6f [2] a4 64 [2] bf 2a [2] 82 }

  condition:
    any of them
}