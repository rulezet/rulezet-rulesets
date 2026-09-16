rule TTP_XOR_MULT_DOSStub_3193 {
  strings:
    $key_3193 = { 65 fb [2] 11 e3 [2] 56 e1 [2] 11 f0 [2] 5f fc [2] 53 f6 [2] 44 fd [2] 5f b3 [2] 62 }

  condition:
    any of them
}