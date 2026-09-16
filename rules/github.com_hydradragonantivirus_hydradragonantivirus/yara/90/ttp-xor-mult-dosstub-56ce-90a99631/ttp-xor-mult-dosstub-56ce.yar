rule TTP_XOR_MULT_DOSStub_56ce {
  strings:
    $key_56ce = { 02 a6 [2] 76 be [2] 31 bc [2] 76 ad [2] 38 a1 [2] 34 ab [2] 23 a0 [2] 38 ee [2] 05 }

  condition:
    any of them
}