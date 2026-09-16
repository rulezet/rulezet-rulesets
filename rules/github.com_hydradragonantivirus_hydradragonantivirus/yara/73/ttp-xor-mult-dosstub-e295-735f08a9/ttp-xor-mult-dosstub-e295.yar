rule TTP_XOR_MULT_DOSStub_e295 {
  strings:
    $key_e295 = { b6 fd [2] c2 e5 [2] 85 e7 [2] c2 f6 [2] 8c fa [2] 80 f0 [2] 97 fb [2] 8c b5 [2] b1 }

  condition:
    any of them
}