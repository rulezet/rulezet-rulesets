rule TTP_XOR_MULT_DOSStub_dc51 {
  strings:
    $key_dc51 = { 88 39 [2] fc 21 [2] bb 23 [2] fc 32 [2] b2 3e [2] be 34 [2] a9 3f [2] b2 71 [2] 8f }

  condition:
    any of them
}