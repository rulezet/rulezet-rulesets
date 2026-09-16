rule TTP_XOR_MULT_DOSStub_55ce {
  strings:
    $key_55ce = { 01 a6 [2] 75 be [2] 32 bc [2] 75 ad [2] 3b a1 [2] 37 ab [2] 20 a0 [2] 3b ee [2] 06 }

  condition:
    any of them
}