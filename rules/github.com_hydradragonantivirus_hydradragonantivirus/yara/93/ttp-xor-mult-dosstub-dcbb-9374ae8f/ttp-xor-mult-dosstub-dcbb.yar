rule TTP_XOR_MULT_DOSStub_dcbb {
  strings:
    $key_dcbb = { 88 d3 [2] fc cb [2] bb c9 [2] fc d8 [2] b2 d4 [2] be de [2] a9 d5 [2] b2 9b [2] 8f }

  condition:
    any of them
}