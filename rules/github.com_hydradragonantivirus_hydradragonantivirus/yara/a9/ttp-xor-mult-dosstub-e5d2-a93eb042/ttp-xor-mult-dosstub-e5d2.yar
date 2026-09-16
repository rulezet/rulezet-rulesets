rule TTP_XOR_MULT_DOSStub_e5d2 {
  strings:
    $key_e5d2 = { b1 ba [2] c5 a2 [2] 82 a0 [2] c5 b1 [2] 8b bd [2] 87 b7 [2] 90 bc [2] 8b f2 [2] b6 }

  condition:
    any of them
}