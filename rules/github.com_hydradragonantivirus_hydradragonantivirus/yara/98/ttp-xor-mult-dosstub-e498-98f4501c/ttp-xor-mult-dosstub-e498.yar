rule TTP_XOR_MULT_DOSStub_e498 {
  strings:
    $key_e498 = { b0 f0 [2] c4 e8 [2] 83 ea [2] c4 fb [2] 8a f7 [2] 86 fd [2] 91 f6 [2] 8a b8 [2] b7 }

  condition:
    any of them
}