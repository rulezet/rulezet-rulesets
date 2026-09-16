rule TTP_XOR_MULT_DOSStub_60ce {
  strings:
    $key_60ce = { 34 a6 [2] 40 be [2] 07 bc [2] 40 ad [2] 0e a1 [2] 02 ab [2] 15 a0 [2] 0e ee [2] 33 }

  condition:
    any of them
}