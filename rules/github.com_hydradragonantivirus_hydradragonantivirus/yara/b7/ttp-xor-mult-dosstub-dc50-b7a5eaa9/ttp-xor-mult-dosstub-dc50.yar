rule TTP_XOR_MULT_DOSStub_dc50 {
  strings:
    $key_dc50 = { 88 38 [2] fc 20 [2] bb 22 [2] fc 33 [2] b2 3f [2] be 35 [2] a9 3e [2] b2 70 [2] 8f }

  condition:
    any of them
}