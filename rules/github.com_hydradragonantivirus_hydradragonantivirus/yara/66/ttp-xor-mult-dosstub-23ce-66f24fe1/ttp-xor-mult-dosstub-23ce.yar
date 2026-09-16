rule TTP_XOR_MULT_DOSStub_23ce {
  strings:
    $key_23ce = { 77 a6 [2] 03 be [2] 44 bc [2] 03 ad [2] 4d a1 [2] 41 ab [2] 56 a0 [2] 4d ee [2] 70 }

  condition:
    any of them
}