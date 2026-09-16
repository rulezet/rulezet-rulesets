rule TTP_XOR_MULT_DOSStub_64ce {
  strings:
    $key_64ce = { 30 a6 [2] 44 be [2] 03 bc [2] 44 ad [2] 0a a1 [2] 06 ab [2] 11 a0 [2] 0a ee [2] 37 }

  condition:
    any of them
}