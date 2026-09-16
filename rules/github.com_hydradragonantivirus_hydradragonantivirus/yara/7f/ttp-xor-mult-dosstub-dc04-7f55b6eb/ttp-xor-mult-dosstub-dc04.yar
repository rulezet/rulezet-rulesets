rule TTP_XOR_MULT_DOSStub_dc04 {
  strings:
    $key_dc04 = { 88 6c [2] fc 74 [2] bb 76 [2] fc 67 [2] b2 6b [2] be 61 [2] a9 6a [2] b2 24 [2] 8f }

  condition:
    any of them
}