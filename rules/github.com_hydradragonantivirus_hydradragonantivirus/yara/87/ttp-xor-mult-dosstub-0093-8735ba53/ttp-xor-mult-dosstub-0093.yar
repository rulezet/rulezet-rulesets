rule TTP_XOR_MULT_DOSStub_0093 {
  strings:
    $key_0093 = { 54 fb [2] 20 e3 [2] 67 e1 [2] 20 f0 [2] 6e fc [2] 62 f6 [2] 75 fd [2] 6e b3 [2] 53 }

  condition:
    any of them
}