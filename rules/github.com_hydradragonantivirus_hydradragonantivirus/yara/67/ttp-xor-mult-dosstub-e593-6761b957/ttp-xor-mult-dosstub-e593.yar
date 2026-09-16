rule TTP_XOR_MULT_DOSStub_e593 {
  strings:
    $key_e593 = { b1 fb [2] c5 e3 [2] 82 e1 [2] c5 f0 [2] 8b fc [2] 87 f6 [2] 90 fd [2] 8b b3 [2] b6 }

  condition:
    any of them
}