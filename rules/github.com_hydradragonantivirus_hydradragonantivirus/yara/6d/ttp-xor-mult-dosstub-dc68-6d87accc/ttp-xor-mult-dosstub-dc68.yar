rule TTP_XOR_MULT_DOSStub_dc68 {
  strings:
    $key_dc68 = { 88 00 [2] fc 18 [2] bb 1a [2] fc 0b [2] b2 07 [2] be 0d [2] a9 06 [2] b2 48 [2] 8f }

  condition:
    any of them
}