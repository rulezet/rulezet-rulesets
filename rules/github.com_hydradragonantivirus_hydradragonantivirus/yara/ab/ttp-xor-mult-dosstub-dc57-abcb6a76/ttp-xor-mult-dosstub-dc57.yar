rule TTP_XOR_MULT_DOSStub_dc57 {
  strings:
    $key_dc57 = { 88 3f [2] fc 27 [2] bb 25 [2] fc 34 [2] b2 38 [2] be 32 [2] a9 39 [2] b2 77 [2] 8f }

  condition:
    any of them
}