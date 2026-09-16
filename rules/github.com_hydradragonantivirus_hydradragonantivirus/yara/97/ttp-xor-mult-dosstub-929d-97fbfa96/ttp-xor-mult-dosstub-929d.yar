rule TTP_XOR_MULT_DOSStub_929d {
  strings:
    $key_929d = { c6 f5 [2] b2 ed [2] f5 ef [2] b2 fe [2] fc f2 [2] f0 f8 [2] e7 f3 [2] fc bd [2] c1 }

  condition:
    any of them
}