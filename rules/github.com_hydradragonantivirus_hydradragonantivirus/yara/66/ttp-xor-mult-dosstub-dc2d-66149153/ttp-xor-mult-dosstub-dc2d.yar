rule TTP_XOR_MULT_DOSStub_dc2d {
  strings:
    $key_dc2d = { 88 45 [2] fc 5d [2] bb 5f [2] fc 4e [2] b2 42 [2] be 48 [2] a9 43 [2] b2 0d [2] 8f }

  condition:
    any of them
}