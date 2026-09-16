rule TTP_XOR_MULT_DOSStub_e3ce {
  strings:
    $key_e3ce = { b7 a6 [2] c3 be [2] 84 bc [2] c3 ad [2] 8d a1 [2] 81 ab [2] 96 a0 [2] 8d ee [2] b0 }

  condition:
    any of them
}