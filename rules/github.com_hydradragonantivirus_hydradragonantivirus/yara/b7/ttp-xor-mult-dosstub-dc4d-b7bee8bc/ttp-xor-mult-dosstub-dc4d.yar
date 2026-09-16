rule TTP_XOR_MULT_DOSStub_dc4d {
  strings:
    $key_dc4d = { 88 25 [2] fc 3d [2] bb 3f [2] fc 2e [2] b2 22 [2] be 28 [2] a9 23 [2] b2 6d [2] 8f }

  condition:
    any of them
}