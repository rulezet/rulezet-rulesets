rule TTP_XOR_MULT_DOSStub_dc36 {
  strings:
    $key_dc36 = { 88 5e [2] fc 46 [2] bb 44 [2] fc 55 [2] b2 59 [2] be 53 [2] a9 58 [2] b2 16 [2] 8f }

  condition:
    any of them
}