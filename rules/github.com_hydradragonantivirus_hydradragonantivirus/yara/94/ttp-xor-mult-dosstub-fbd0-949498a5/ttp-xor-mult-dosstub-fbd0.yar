rule TTP_XOR_MULT_DOSStub_fbd0 {
  strings:
    $key_fbd0 = { af b8 [2] db a0 [2] 9c a2 [2] db b3 [2] 95 bf [2] 99 b5 [2] 8e be [2] 95 f0 [2] a8 }

  condition:
    any of them
}