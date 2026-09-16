rule TTP_XOR_MULT_DOSStub_dc0a {
  strings:
    $key_dc0a = { 88 62 [2] fc 7a [2] bb 78 [2] fc 69 [2] b2 65 [2] be 6f [2] a9 64 [2] b2 2a [2] 8f }

  condition:
    any of them
}