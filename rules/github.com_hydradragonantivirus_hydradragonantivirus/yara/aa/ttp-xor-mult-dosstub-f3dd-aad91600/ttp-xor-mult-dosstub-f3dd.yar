rule TTP_XOR_MULT_DOSStub_f3dd {
  strings:
    $key_f3dd = { a7 b5 [2] d3 ad [2] 94 af [2] d3 be [2] 9d b2 [2] 91 b8 [2] 86 b3 [2] 9d fd [2] a0 }

  condition:
    any of them
}