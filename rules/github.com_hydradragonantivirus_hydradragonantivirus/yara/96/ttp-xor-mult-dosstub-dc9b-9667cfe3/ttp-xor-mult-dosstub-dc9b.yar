rule TTP_XOR_MULT_DOSStub_dc9b {
  strings:
    $key_dc9b = { 88 f3 [2] fc eb [2] bb e9 [2] fc f8 [2] b2 f4 [2] be fe [2] a9 f5 [2] b2 bb [2] 8f }

  condition:
    any of them
}