rule TTP_XOR_MULT_DOSStub_b39d {
  strings:
    $key_b39d = { e7 f5 [2] 93 ed [2] d4 ef [2] 93 fe [2] dd f2 [2] d1 f8 [2] c6 f3 [2] dd bd [2] e0 }

  condition:
    any of them
}