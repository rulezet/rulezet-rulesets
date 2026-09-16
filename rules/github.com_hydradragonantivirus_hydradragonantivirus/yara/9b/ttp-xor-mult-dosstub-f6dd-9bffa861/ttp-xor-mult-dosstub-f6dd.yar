rule TTP_XOR_MULT_DOSStub_f6dd {
  strings:
    $key_f6dd = { a2 b5 [2] d6 ad [2] 91 af [2] d6 be [2] 98 b2 [2] 94 b8 [2] 83 b3 [2] 98 fd [2] a5 }

  condition:
    any of them
}