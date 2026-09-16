rule TTP_XOR_MULT_DOSStub_1493 {
  strings:
    $key_1493 = { 40 fb [2] 34 e3 [2] 73 e1 [2] 34 f0 [2] 7a fc [2] 76 f6 [2] 61 fd [2] 7a b3 [2] 47 }

  condition:
    any of them
}