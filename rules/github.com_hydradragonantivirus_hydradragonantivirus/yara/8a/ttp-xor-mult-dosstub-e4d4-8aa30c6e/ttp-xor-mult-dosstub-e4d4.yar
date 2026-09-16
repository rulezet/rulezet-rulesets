rule TTP_XOR_MULT_DOSStub_e4d4 {
  strings:
    $key_e4d4 = { b0 bc [2] c4 a4 [2] 83 a6 [2] c4 b7 [2] 8a bb [2] 86 b1 [2] 91 ba [2] 8a f4 [2] b7 }

  condition:
    any of them
}