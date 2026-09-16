rule TTP_XOR_MULT_DOSStub_b081 {
  strings:
    $key_b081 = { e4 e9 [2] 90 f1 [2] d7 f3 [2] 90 e2 [2] de ee [2] d2 e4 [2] c5 ef [2] de a1 [2] e3 }

  condition:
    any of them
}