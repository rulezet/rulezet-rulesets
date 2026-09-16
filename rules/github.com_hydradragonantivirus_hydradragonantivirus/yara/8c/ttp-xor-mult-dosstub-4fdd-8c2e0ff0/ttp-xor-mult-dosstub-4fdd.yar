rule TTP_XOR_MULT_DOSStub_4fdd {
  strings:
    $key_4fdd = { 1b b5 [2] 6f ad [2] 28 af [2] 6f be [2] 21 b2 [2] 2d b8 [2] 3a b3 [2] 21 fd [2] 1c }

  condition:
    any of them
}