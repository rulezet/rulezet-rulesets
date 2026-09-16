rule TTP_XOR_MULT_DOSStub_3fdd {
  strings:
    $key_3fdd = { 6b b5 [2] 1f ad [2] 58 af [2] 1f be [2] 51 b2 [2] 5d b8 [2] 4a b3 [2] 51 fd [2] 6c }

  condition:
    any of them
}