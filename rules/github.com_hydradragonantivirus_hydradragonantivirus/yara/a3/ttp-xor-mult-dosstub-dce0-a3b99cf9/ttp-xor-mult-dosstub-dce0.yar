rule TTP_XOR_MULT_DOSStub_dce0 {
  strings:
    $key_dce0 = { 88 88 [2] fc 90 [2] bb 92 [2] fc 83 [2] b2 8f [2] be 85 [2] a9 8e [2] b2 c0 [2] 8f }

  condition:
    any of them
}