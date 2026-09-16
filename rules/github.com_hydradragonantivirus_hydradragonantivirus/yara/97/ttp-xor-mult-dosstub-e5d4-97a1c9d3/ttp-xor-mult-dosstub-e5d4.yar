rule TTP_XOR_MULT_DOSStub_e5d4 {
  strings:
    $key_e5d4 = { b1 bc [2] c5 a4 [2] 82 a6 [2] c5 b7 [2] 8b bb [2] 87 b1 [2] 90 ba [2] 8b f4 [2] b6 }

  condition:
    any of them
}