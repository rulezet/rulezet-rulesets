rule TTP_XOR_MULT_DOSStub_dc13 {
  strings:
    $key_dc13 = { 88 7b [2] fc 63 [2] bb 61 [2] fc 70 [2] b2 7c [2] be 76 [2] a9 7d [2] b2 33 [2] 8f }

  condition:
    any of them
}