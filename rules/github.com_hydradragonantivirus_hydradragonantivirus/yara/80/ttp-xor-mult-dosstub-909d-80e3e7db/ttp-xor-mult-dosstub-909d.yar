rule TTP_XOR_MULT_DOSStub_909d {
  strings:
    $key_909d = { c4 f5 [2] b0 ed [2] f7 ef [2] b0 fe [2] fe f2 [2] f2 f8 [2] e5 f3 [2] fe bd [2] c3 }

  condition:
    any of them
}