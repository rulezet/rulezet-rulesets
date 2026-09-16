rule TTP_XOR_MULT_DOSStub_c493 {
  strings:
    $key_c493 = { 90 fb [2] e4 e3 [2] a3 e1 [2] e4 f0 [2] aa fc [2] a6 f6 [2] b1 fd [2] aa b3 [2] 97 }

  condition:
    any of them
}