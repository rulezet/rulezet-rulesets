rule TTP_XOR_MULT_DOSStub_50dd {
  strings:
    $key_50dd = { 04 b5 [2] 70 ad [2] 37 af [2] 70 be [2] 3e b2 [2] 32 b8 [2] 25 b3 [2] 3e fd [2] 03 }

  condition:
    any of them
}