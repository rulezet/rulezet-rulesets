rule TTP_XOR_MULT_DOSStub_dcfa {
  strings:
    $key_dcfa = { 88 92 [2] fc 8a [2] bb 88 [2] fc 99 [2] b2 95 [2] be 9f [2] a9 94 [2] b2 da [2] 8f }

  condition:
    any of them
}