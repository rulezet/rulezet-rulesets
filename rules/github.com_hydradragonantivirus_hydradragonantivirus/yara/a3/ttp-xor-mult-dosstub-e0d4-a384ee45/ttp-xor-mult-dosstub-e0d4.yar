rule TTP_XOR_MULT_DOSStub_e0d4 {
  strings:
    $key_e0d4 = { b4 bc [2] c0 a4 [2] 87 a6 [2] c0 b7 [2] 8e bb [2] 82 b1 [2] 95 ba [2] 8e f4 [2] b3 }

  condition:
    any of them
}