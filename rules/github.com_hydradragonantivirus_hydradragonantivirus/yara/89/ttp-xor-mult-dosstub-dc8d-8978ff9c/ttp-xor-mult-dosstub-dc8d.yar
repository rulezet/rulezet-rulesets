rule TTP_XOR_MULT_DOSStub_dc8d {
  strings:
    $key_dc8d = { 88 e5 [2] fc fd [2] bb ff [2] fc ee [2] b2 e2 [2] be e8 [2] a9 e3 [2] b2 ad [2] 8f }

  condition:
    any of them
}