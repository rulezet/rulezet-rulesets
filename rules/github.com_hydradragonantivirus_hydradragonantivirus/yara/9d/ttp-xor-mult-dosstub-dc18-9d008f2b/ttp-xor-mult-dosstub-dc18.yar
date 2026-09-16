rule TTP_XOR_MULT_DOSStub_dc18 {
  strings:
    $key_dc18 = { 88 70 [2] fc 68 [2] bb 6a [2] fc 7b [2] b2 77 [2] be 7d [2] a9 76 [2] b2 38 [2] 8f }

  condition:
    any of them
}