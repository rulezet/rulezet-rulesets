rule TTP_XOR_MULT_DOSStub_35ce {
  strings:
    $key_35ce = { 61 a6 [2] 15 be [2] 52 bc [2] 15 ad [2] 5b a1 [2] 57 ab [2] 40 a0 [2] 5b ee [2] 66 }

  condition:
    any of them
}