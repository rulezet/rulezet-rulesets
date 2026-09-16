rule TTP_XOR_MULT_DOSStub_f195 {
  strings:
    $key_f195 = { a5 fd [2] d1 e5 [2] 96 e7 [2] d1 f6 [2] 9f fa [2] 93 f0 [2] 84 fb [2] 9f b5 [2] a2 }

  condition:
    any of them
}