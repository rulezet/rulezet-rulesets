rule TTP_XOR_MULT_DOSStub_d09b {
  strings:
    $key_d09b = { 84 f3 [2] f0 eb [2] b7 e9 [2] f0 f8 [2] be f4 [2] b2 fe [2] a5 f5 [2] be bb [2] 83 }

  condition:
    any of them
}