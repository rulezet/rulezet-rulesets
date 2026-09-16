rule TTP_XOR_MULT_DOSStub_0293 {
  strings:
    $key_0293 = { 56 fb [2] 22 e3 [2] 65 e1 [2] 22 f0 [2] 6c fc [2] 60 f6 [2] 77 fd [2] 6c b3 [2] 51 }

  condition:
    any of them
}