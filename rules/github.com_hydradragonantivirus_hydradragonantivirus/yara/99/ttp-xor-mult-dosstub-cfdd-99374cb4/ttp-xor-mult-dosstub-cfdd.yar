rule TTP_XOR_MULT_DOSStub_cfdd {
  strings:
    $key_cfdd = { 9b b5 [2] ef ad [2] a8 af [2] ef be [2] a1 b2 [2] ad b8 [2] ba b3 [2] a1 fd [2] 9c }

  condition:
    any of them
}