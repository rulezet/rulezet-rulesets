rule TTP_XOR_MULT_DOSStub_dc20 {
  strings:
    $key_dc20 = { 88 48 [2] fc 50 [2] bb 52 [2] fc 43 [2] b2 4f [2] be 45 [2] a9 4e [2] b2 00 [2] 8f }

  condition:
    any of them
}