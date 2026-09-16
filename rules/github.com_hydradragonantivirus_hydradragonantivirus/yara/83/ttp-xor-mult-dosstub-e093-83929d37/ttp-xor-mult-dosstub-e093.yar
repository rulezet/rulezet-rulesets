rule TTP_XOR_MULT_DOSStub_e093 {
  strings:
    $key_e093 = { b4 fb [2] c0 e3 [2] 87 e1 [2] c0 f0 [2] 8e fc [2] 82 f6 [2] 95 fd [2] 8e b3 [2] b3 }

  condition:
    any of them
}