rule TTP_XOR_MULT_DOSStub_959d {
  strings:
    $key_959d = { c1 f5 [2] b5 ed [2] f2 ef [2] b5 fe [2] fb f2 [2] f7 f8 [2] e0 f3 [2] fb bd [2] c6 }

  condition:
    any of them
}