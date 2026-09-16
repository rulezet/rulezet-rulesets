rule TTP_XOR_MULT_DOSStub_dce7 {
  strings:
    $key_dce7 = { 88 8f [2] fc 97 [2] bb 95 [2] fc 84 [2] b2 88 [2] be 82 [2] a9 89 [2] b2 c7 [2] 8f }

  condition:
    any of them
}