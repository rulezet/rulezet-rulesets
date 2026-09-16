rule TTP_XOR_MULT_DOSStub_dc72 {
  strings:
    $key_dc72 = { 88 1a [2] fc 02 [2] bb 00 [2] fc 11 [2] b2 1d [2] be 17 [2] a9 1c [2] b2 52 [2] 8f }

  condition:
    any of them
}