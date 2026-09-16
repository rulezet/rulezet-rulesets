rule TTP_XOR_MULT_DOSStub_dc1a {
  strings:
    $key_dc1a = { 88 72 [2] fc 6a [2] bb 68 [2] fc 79 [2] b2 75 [2] be 7f [2] a9 74 [2] b2 3a [2] 8f }

  condition:
    any of them
}