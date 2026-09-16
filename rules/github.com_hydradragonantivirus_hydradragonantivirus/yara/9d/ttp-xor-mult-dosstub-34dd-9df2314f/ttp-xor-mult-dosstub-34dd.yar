rule TTP_XOR_MULT_DOSStub_34dd {
  strings:
    $key_34dd = { 60 b5 [2] 14 ad [2] 53 af [2] 14 be [2] 5a b2 [2] 56 b8 [2] 41 b3 [2] 5a fd [2] 67 }

  condition:
    any of them
}