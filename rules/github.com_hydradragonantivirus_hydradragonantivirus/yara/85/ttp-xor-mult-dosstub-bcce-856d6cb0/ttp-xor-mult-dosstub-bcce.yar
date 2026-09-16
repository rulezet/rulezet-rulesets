rule TTP_XOR_MULT_DOSStub_bcce {
  strings:
    $key_bcce = { e8 a6 [2] 9c be [2] db bc [2] 9c ad [2] d2 a1 [2] de ab [2] c9 a0 [2] d2 ee [2] ef }

  condition:
    any of them
}