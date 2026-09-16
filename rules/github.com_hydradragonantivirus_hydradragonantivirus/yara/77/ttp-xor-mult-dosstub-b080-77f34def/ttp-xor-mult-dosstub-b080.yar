rule TTP_XOR_MULT_DOSStub_b080 {
  strings:
    $key_b080 = { e4 e8 [2] 90 f0 [2] d7 f2 [2] 90 e3 [2] de ef [2] d2 e5 [2] c5 ee [2] de a0 [2] e3 }

  condition:
    any of them
}