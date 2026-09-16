rule TTP_XOR_MULT_DOSStub_dce5 {
  strings:
    $key_dce5 = { 88 8d [2] fc 95 [2] bb 97 [2] fc 86 [2] b2 8a [2] be 80 [2] a9 8b [2] b2 c5 [2] 8f }

  condition:
    any of them
}