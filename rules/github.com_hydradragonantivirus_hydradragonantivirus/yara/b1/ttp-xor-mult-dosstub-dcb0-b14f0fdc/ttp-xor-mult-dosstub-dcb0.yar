rule TTP_XOR_MULT_DOSStub_dcb0 {
  strings:
    $key_dcb0 = { 88 d8 [2] fc c0 [2] bb c2 [2] fc d3 [2] b2 df [2] be d5 [2] a9 de [2] b2 90 [2] 8f }

  condition:
    any of them
}