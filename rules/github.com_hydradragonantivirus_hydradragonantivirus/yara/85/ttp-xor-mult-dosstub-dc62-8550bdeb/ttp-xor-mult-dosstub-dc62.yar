rule TTP_XOR_MULT_DOSStub_dc62 {
  strings:
    $key_dc62 = { 88 0a [2] fc 12 [2] bb 10 [2] fc 01 [2] b2 0d [2] be 07 [2] a9 0c [2] b2 42 [2] 8f }

  condition:
    any of them
}