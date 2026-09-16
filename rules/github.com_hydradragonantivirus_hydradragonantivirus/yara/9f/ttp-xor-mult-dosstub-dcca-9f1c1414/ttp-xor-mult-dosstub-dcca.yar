rule TTP_XOR_MULT_DOSStub_dcca {
  strings:
    $key_dcca = { 88 a2 [2] fc ba [2] bb b8 [2] fc a9 [2] b2 a5 [2] be af [2] a9 a4 [2] b2 ea [2] 8f }

  condition:
    any of them
}