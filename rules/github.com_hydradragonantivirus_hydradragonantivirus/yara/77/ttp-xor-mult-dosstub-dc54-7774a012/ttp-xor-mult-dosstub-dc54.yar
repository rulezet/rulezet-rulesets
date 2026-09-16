rule TTP_XOR_MULT_DOSStub_dc54 {
  strings:
    $key_dc54 = { 88 3c [2] fc 24 [2] bb 26 [2] fc 37 [2] b2 3b [2] be 31 [2] a9 3a [2] b2 74 [2] 8f }

  condition:
    any of them
}