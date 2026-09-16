rule TTP_XOR_MULT_DOSStub_10dd {
  strings:
    $key_10dd = { 44 b5 [2] 30 ad [2] 77 af [2] 30 be [2] 7e b2 [2] 72 b8 [2] 65 b3 [2] 7e fd [2] 43 }

  condition:
    any of them
}