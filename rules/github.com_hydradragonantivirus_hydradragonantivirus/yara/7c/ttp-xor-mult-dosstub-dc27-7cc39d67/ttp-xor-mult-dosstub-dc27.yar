rule TTP_XOR_MULT_DOSStub_dc27 {
  strings:
    $key_dc27 = { 88 4f [2] fc 57 [2] bb 55 [2] fc 44 [2] b2 48 [2] be 42 [2] a9 49 [2] b2 07 [2] 8f }

  condition:
    any of them
}