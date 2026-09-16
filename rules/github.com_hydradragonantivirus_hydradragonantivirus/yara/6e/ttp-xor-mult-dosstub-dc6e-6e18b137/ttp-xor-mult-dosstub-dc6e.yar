rule TTP_XOR_MULT_DOSStub_dc6e {
  strings:
    $key_dc6e = { 88 06 [2] fc 1e [2] bb 1c [2] fc 0d [2] b2 01 [2] be 0b [2] a9 00 [2] b2 4e [2] 8f }

  condition:
    any of them
}