rule TTP_XOR_MULT_DOSStub_dc5f {
  strings:
    $key_dc5f = { 88 37 [2] fc 2f [2] bb 2d [2] fc 3c [2] b2 30 [2] be 3a [2] a9 31 [2] b2 7f [2] 8f }

  condition:
    any of them
}