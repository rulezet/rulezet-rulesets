rule TTP_XOR_MULT_DOSStub_f093 {
  strings:
    $key_f093 = { a4 fb [2] d0 e3 [2] 97 e1 [2] d0 f0 [2] 9e fc [2] 92 f6 [2] 85 fd [2] 9e b3 [2] a3 }

  condition:
    any of them
}