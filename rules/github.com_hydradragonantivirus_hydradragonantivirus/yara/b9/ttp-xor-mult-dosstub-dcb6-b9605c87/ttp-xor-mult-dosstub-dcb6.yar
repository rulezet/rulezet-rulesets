rule TTP_XOR_MULT_DOSStub_dcb6 {
  strings:
    $key_dcb6 = { 88 de [2] fc c6 [2] bb c4 [2] fc d5 [2] b2 d9 [2] be d3 [2] a9 d8 [2] b2 96 [2] 8f }

  condition:
    any of them
}