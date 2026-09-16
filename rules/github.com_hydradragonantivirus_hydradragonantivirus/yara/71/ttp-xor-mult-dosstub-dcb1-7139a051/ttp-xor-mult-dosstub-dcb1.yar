rule TTP_XOR_MULT_DOSStub_dcb1 {
  strings:
    $key_dcb1 = { 88 d9 [2] fc c1 [2] bb c3 [2] fc d2 [2] b2 de [2] be d4 [2] a9 df [2] b2 91 [2] 8f }

  condition:
    any of them
}