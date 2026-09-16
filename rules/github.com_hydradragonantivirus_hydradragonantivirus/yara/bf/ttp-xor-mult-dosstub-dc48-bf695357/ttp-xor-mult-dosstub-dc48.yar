rule TTP_XOR_MULT_DOSStub_dc48 {
  strings:
    $key_dc48 = { 88 20 [2] fc 38 [2] bb 3a [2] fc 2b [2] b2 27 [2] be 2d [2] a9 26 [2] b2 68 [2] 8f }

  condition:
    any of them
}