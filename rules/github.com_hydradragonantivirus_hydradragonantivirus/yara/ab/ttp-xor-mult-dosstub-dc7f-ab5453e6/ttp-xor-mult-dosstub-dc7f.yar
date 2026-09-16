rule TTP_XOR_MULT_DOSStub_dc7f {
  strings:
    $key_dc7f = { 88 17 [2] fc 0f [2] bb 0d [2] fc 1c [2] b2 10 [2] be 1a [2] a9 11 [2] b2 5f [2] 8f }

  condition:
    any of them
}