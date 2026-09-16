rule TTP_XOR_MULT_DOSStub_dc7e {
  strings:
    $key_dc7e = { 88 16 [2] fc 0e [2] bb 0c [2] fc 1d [2] b2 11 [2] be 1b [2] a9 10 [2] b2 5e [2] 8f }

  condition:
    any of them
}