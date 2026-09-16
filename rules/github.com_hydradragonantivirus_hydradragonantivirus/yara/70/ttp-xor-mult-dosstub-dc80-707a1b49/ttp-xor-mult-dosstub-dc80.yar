rule TTP_XOR_MULT_DOSStub_dc80 {
  strings:
    $key_dc80 = { 88 e8 [2] fc f0 [2] bb f2 [2] fc e3 [2] b2 ef [2] be e5 [2] a9 ee [2] b2 a0 [2] 8f }

  condition:
    any of them
}