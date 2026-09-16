rule TTP_XOR_MULT_DOSStub_36dd {
  strings:
    $key_36dd = { 62 b5 [2] 16 ad [2] 51 af [2] 16 be [2] 58 b2 [2] 54 b8 [2] 43 b3 [2] 58 fd [2] 65 }

  condition:
    any of them
}