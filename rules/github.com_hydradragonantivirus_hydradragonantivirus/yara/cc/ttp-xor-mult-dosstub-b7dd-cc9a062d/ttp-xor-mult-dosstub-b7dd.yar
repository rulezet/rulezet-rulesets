rule TTP_XOR_MULT_DOSStub_b7dd {
  strings:
    $key_b7dd = { e3 b5 [2] 97 ad [2] d0 af [2] 97 be [2] d9 b2 [2] d5 b8 [2] c2 b3 [2] d9 fd [2] e4 }

  condition:
    any of them
}