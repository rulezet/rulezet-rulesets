rule TTP_XOR_MULT_DOSStub_dc05 {
  strings:
    $key_dc05 = { 88 6d [2] fc 75 [2] bb 77 [2] fc 66 [2] b2 6a [2] be 60 [2] a9 6b [2] b2 25 [2] 8f }

  condition:
    any of them
}