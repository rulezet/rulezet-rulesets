rule TTP_XOR_MULT_DOSStub_dc5d {
  strings:
    $key_dc5d = { 88 35 [2] fc 2d [2] bb 2f [2] fc 3e [2] b2 32 [2] be 38 [2] a9 33 [2] b2 7d [2] 8f }

  condition:
    any of them
}