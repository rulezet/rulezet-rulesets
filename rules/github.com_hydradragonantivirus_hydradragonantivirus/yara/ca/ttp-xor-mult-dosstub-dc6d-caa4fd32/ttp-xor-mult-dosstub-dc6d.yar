rule TTP_XOR_MULT_DOSStub_dc6d {
  strings:
    $key_dc6d = { 88 05 [2] fc 1d [2] bb 1f [2] fc 0e [2] b2 02 [2] be 08 [2] a9 03 [2] b2 4d [2] 8f }

  condition:
    any of them
}