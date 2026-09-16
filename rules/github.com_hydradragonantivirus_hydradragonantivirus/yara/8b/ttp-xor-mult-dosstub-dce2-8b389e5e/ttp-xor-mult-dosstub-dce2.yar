rule TTP_XOR_MULT_DOSStub_dce2 {
  strings:
    $key_dce2 = { 88 8a [2] fc 92 [2] bb 90 [2] fc 81 [2] b2 8d [2] be 87 [2] a9 8c [2] b2 c2 [2] 8f }

  condition:
    any of them
}