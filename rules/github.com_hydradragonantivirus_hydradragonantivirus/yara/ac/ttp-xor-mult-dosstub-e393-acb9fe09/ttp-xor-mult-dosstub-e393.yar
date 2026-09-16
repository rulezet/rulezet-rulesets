rule TTP_XOR_MULT_DOSStub_e393 {
  strings:
    $key_e393 = { b7 fb [2] c3 e3 [2] 84 e1 [2] c3 f0 [2] 8d fc [2] 81 f6 [2] 96 fd [2] 8d b3 [2] b0 }

  condition:
    any of them
}