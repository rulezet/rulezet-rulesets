rule TTP_XOR_MULT_DOSStub_d49d {
  strings:
    $key_d49d = { 80 f5 [2] f4 ed [2] b3 ef [2] f4 fe [2] ba f2 [2] b6 f8 [2] a1 f3 [2] ba bd [2] 87 }

  condition:
    any of them
}