rule TTP_XOR_MULT_DOSStub_4193 {
  strings:
    $key_4193 = { 15 fb [2] 61 e3 [2] 26 e1 [2] 61 f0 [2] 2f fc [2] 23 f6 [2] 34 fd [2] 2f b3 [2] 12 }

  condition:
    any of them
}