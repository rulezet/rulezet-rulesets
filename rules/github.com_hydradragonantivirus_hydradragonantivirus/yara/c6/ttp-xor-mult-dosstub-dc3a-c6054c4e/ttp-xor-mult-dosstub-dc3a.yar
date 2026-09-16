rule TTP_XOR_MULT_DOSStub_dc3a {
  strings:
    $key_dc3a = { 88 52 [2] fc 4a [2] bb 48 [2] fc 59 [2] b2 55 [2] be 5f [2] a9 54 [2] b2 1a [2] 8f }

  condition:
    any of them
}