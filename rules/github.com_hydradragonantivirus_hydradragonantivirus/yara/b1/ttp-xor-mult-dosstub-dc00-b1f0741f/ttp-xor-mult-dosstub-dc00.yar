rule TTP_XOR_MULT_DOSStub_dc00 {
  strings:
    $key_dc00 = { 88 68 [2] fc 70 [2] bb 72 [2] fc 63 [2] b2 6f [2] be 65 [2] a9 6e [2] b2 20 [2] 8f }

  condition:
    any of them
}