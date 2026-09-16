rule TTP_XOR_MULT_DOSStub_0fdd {
  strings:
    $key_0fdd = { 5b b5 [2] 2f ad [2] 68 af [2] 2f be [2] 61 b2 [2] 6d b8 [2] 7a b3 [2] 61 fd [2] 5c }

  condition:
    any of them
}