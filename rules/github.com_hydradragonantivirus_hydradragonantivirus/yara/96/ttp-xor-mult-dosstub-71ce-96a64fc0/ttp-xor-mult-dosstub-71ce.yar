rule TTP_XOR_MULT_DOSStub_71ce {
  strings:
    $key_71ce = { 25 a6 [2] 51 be [2] 16 bc [2] 51 ad [2] 1f a1 [2] 13 ab [2] 04 a0 [2] 1f ee [2] 22 }

  condition:
    any of them
}