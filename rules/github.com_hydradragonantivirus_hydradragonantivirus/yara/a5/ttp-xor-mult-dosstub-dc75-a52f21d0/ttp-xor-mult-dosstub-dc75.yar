rule TTP_XOR_MULT_DOSStub_dc75 {
  strings:
    $key_dc75 = { 88 1d [2] fc 05 [2] bb 07 [2] fc 16 [2] b2 1a [2] be 10 [2] a9 1b [2] b2 55 [2] 8f }

  condition:
    any of them
}