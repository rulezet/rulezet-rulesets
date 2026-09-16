rule TTP_XOR_MULT_DOSStub_01ce {
  strings:
    $key_01ce = { 55 a6 [2] 21 be [2] 66 bc [2] 21 ad [2] 6f a1 [2] 63 ab [2] 74 a0 [2] 6f ee [2] 52 }

  condition:
    any of them
}