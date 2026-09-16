rule TTP_XOR_MULT_DOSStub_dce6 {
  strings:
    $key_dce6 = { 88 8e [2] fc 96 [2] bb 94 [2] fc 85 [2] b2 89 [2] be 83 [2] a9 88 [2] b2 c6 [2] 8f }

  condition:
    any of them
}