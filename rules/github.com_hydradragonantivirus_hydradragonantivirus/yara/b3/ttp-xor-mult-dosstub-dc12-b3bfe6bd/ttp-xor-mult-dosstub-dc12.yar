rule TTP_XOR_MULT_DOSStub_dc12 {
  strings:
    $key_dc12 = { 88 7a [2] fc 62 [2] bb 60 [2] fc 71 [2] b2 7d [2] be 77 [2] a9 7c [2] b2 32 [2] 8f }

  condition:
    any of them
}