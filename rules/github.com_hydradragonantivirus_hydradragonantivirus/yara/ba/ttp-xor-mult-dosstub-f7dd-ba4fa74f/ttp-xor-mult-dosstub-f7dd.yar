rule TTP_XOR_MULT_DOSStub_f7dd {
  strings:
    $key_f7dd = { a3 b5 [2] d7 ad [2] 90 af [2] d7 be [2] 99 b2 [2] 95 b8 [2] 82 b3 [2] 99 fd [2] a4 }

  condition:
    any of them
}