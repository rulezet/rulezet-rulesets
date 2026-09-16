rule TTP_XOR_MULT_DOSStub_63ce {
  strings:
    $key_63ce = { 37 a6 [2] 43 be [2] 04 bc [2] 43 ad [2] 0d a1 [2] 01 ab [2] 16 a0 [2] 0d ee [2] 30 }

  condition:
    any of them
}