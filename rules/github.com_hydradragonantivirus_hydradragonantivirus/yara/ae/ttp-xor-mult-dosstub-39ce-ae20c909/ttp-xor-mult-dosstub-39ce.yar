rule TTP_XOR_MULT_DOSStub_39ce {
  strings:
    $key_39ce = { 6d a6 [2] 19 be [2] 5e bc [2] 19 ad [2] 57 a1 [2] 5b ab [2] 4c a0 [2] 57 ee [2] 6a }

  condition:
    any of them
}