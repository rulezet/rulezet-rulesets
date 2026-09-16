rule TTP_XOR_MULT_DOSStub_24dd {
  strings:
    $key_24dd = { 70 b5 [2] 04 ad [2] 43 af [2] 04 be [2] 4a b2 [2] 46 b8 [2] 51 b3 [2] 4a fd [2] 77 }

  condition:
    any of them
}