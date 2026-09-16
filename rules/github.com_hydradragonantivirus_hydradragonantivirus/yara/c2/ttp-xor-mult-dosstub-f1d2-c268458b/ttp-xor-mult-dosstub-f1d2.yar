rule TTP_XOR_MULT_DOSStub_f1d2 {
  strings:
    $key_f1d2 = { a5 ba [2] d1 a2 [2] 96 a0 [2] d1 b1 [2] 9f bd [2] 93 b7 [2] 84 bc [2] 9f f2 [2] a2 }

  condition:
    any of them
}