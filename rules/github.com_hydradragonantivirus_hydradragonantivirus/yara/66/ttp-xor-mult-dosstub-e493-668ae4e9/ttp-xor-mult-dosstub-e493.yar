rule TTP_XOR_MULT_DOSStub_e493 {
  strings:
    $key_e493 = { b0 fb [2] c4 e3 [2] 83 e1 [2] c4 f0 [2] 8a fc [2] 86 f6 [2] 91 fd [2] 8a b3 [2] b7 }

  condition:
    any of them
}