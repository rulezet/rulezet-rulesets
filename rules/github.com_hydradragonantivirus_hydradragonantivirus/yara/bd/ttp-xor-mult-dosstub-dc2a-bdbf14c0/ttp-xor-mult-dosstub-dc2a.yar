rule TTP_XOR_MULT_DOSStub_dc2a {
  strings:
    $key_dc2a = { 88 42 [2] fc 5a [2] bb 58 [2] fc 49 [2] b2 45 [2] be 4f [2] a9 44 [2] b2 0a [2] 8f }

  condition:
    any of them
}