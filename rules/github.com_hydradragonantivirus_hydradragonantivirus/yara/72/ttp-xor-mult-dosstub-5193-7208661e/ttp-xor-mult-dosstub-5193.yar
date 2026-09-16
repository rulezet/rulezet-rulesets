rule TTP_XOR_MULT_DOSStub_5193 {
  strings:
    $key_5193 = { 05 fb [2] 71 e3 [2] 36 e1 [2] 71 f0 [2] 3f fc [2] 33 f6 [2] 24 fd [2] 3f b3 [2] 02 }

  condition:
    any of them
}