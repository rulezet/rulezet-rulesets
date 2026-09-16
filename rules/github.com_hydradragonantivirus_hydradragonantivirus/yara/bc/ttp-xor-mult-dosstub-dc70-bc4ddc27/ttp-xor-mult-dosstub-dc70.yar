rule TTP_XOR_MULT_DOSStub_dc70 {
  strings:
    $key_dc70 = { 88 18 [2] fc 00 [2] bb 02 [2] fc 13 [2] b2 1f [2] be 15 [2] a9 1e [2] b2 50 [2] 8f }

  condition:
    any of them
}