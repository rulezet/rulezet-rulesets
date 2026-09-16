rule TTP_XOR_MULT_DOSStub_13ce {
  strings:
    $key_13ce = { 47 a6 [2] 33 be [2] 74 bc [2] 33 ad [2] 7d a1 [2] 71 ab [2] 66 a0 [2] 7d ee [2] 40 }

  condition:
    any of them
}