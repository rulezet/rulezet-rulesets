rule TTP_XOR_MULT_DOSStub_16ce {
  strings:
    $key_16ce = { 42 a6 [2] 36 be [2] 71 bc [2] 36 ad [2] 78 a1 [2] 74 ab [2] 63 a0 [2] 78 ee [2] 45 }

  condition:
    any of them
}