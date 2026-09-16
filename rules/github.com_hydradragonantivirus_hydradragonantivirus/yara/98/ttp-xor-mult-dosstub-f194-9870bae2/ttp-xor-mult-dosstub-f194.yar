rule TTP_XOR_MULT_DOSStub_f194 {
  strings:
    $key_f194 = { a5 fc [2] d1 e4 [2] 96 e6 [2] d1 f7 [2] 9f fb [2] 93 f1 [2] 84 fa [2] 9f b4 [2] a2 }

  condition:
    any of them
}