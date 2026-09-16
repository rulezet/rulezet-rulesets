rule TTP_XOR_MULT_DOSStub_dc38 {
  strings:
    $key_dc38 = { 88 50 [2] fc 48 [2] bb 4a [2] fc 5b [2] b2 57 [2] be 5d [2] a9 56 [2] b2 18 [2] 8f }

  condition:
    any of them
}