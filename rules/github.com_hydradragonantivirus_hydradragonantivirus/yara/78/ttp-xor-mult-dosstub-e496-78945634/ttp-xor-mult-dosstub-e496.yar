rule TTP_XOR_MULT_DOSStub_e496 {
  strings:
    $key_e496 = { b0 fe [2] c4 e6 [2] 83 e4 [2] c4 f5 [2] 8a f9 [2] 86 f3 [2] 91 f8 [2] 8a b6 [2] b7 }

  condition:
    any of them
}