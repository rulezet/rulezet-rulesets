rule TTP_XOR_MULT_DOSStub_e8dd {
  strings:
    $key_e8dd = { bc b5 [2] c8 ad [2] 8f af [2] c8 be [2] 86 b2 [2] 8a b8 [2] 9d b3 [2] 86 fd [2] bb }

  condition:
    any of them
}