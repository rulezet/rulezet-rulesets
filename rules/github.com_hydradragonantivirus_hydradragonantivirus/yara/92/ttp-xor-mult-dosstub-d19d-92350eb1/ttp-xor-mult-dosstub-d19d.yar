rule TTP_XOR_MULT_DOSStub_d19d {
  strings:
    $key_d19d = { 85 f5 [2] f1 ed [2] b6 ef [2] f1 fe [2] bf f2 [2] b3 f8 [2] a4 f3 [2] bf bd [2] 82 }

  condition:
    any of them
}