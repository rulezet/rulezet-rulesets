rule TTP_XOR_MULT_DOSStub_dc82 {
  strings:
    $key_dc82 = { 88 ea [2] fc f2 [2] bb f0 [2] fc e1 [2] b2 ed [2] be e7 [2] a9 ec [2] b2 a2 [2] 8f }

  condition:
    any of them
}