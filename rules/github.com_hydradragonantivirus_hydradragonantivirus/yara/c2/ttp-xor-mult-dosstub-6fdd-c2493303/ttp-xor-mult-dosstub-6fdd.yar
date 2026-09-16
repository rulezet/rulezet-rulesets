rule TTP_XOR_MULT_DOSStub_6fdd {
  strings:
    $key_6fdd = { 3b b5 [2] 4f ad [2] 08 af [2] 4f be [2] 01 b2 [2] 0d b8 [2] 1a b3 [2] 01 fd [2] 3c }

  condition:
    any of them
}