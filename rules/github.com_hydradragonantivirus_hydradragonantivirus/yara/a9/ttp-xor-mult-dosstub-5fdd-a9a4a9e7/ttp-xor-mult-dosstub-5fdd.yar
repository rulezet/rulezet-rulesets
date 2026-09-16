rule TTP_XOR_MULT_DOSStub_5fdd {
  strings:
    $key_5fdd = { 0b b5 [2] 7f ad [2] 38 af [2] 7f be [2] 31 b2 [2] 3d b8 [2] 2a b3 [2] 31 fd [2] 0c }

  condition:
    any of them
}