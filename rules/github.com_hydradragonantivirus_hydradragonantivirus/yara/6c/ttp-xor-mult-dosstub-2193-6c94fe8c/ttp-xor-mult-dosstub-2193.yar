rule TTP_XOR_MULT_DOSStub_2193 {
  strings:
    $key_2193 = { 75 fb [2] 01 e3 [2] 46 e1 [2] 01 f0 [2] 4f fc [2] 43 f6 [2] 54 fd [2] 4f b3 [2] 72 }

  condition:
    any of them
}