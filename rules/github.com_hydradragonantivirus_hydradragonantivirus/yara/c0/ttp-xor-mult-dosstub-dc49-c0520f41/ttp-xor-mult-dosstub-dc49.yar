rule TTP_XOR_MULT_DOSStub_dc49 {
  strings:
    $key_dc49 = { 88 21 [2] fc 39 [2] bb 3b [2] fc 2a [2] b2 26 [2] be 2c [2] a9 27 [2] b2 69 [2] 8f }

  condition:
    any of them
}