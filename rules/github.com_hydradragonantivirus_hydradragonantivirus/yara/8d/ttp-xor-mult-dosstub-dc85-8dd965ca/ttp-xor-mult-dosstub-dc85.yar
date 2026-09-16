rule TTP_XOR_MULT_DOSStub_dc85 {
  strings:
    $key_dc85 = { 88 ed [2] fc f5 [2] bb f7 [2] fc e6 [2] b2 ea [2] be e0 [2] a9 eb [2] b2 a5 [2] 8f }

  condition:
    any of them
}