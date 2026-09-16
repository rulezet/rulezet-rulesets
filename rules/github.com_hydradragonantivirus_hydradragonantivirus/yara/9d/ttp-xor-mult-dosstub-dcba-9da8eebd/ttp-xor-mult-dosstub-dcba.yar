rule TTP_XOR_MULT_DOSStub_dcba {
  strings:
    $key_dcba = { 88 d2 [2] fc ca [2] bb c8 [2] fc d9 [2] b2 d5 [2] be df [2] a9 d4 [2] b2 9a [2] 8f }

  condition:
    any of them
}