rule TTP_XOR_MULT_DOSStub_0793 {
  strings:
    $key_0793 = { 53 fb [2] 27 e3 [2] 60 e1 [2] 27 f0 [2] 69 fc [2] 65 f6 [2] 72 fd [2] 69 b3 [2] 54 }

  condition:
    any of them
}