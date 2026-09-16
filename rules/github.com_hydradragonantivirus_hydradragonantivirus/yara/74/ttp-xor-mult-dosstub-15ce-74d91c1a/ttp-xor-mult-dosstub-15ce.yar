rule TTP_XOR_MULT_DOSStub_15ce {
  strings:
    $key_15ce = { 41 a6 [2] 35 be [2] 72 bc [2] 35 ad [2] 7b a1 [2] 77 ab [2] 60 a0 [2] 7b ee [2] 46 }

  condition:
    any of them
}