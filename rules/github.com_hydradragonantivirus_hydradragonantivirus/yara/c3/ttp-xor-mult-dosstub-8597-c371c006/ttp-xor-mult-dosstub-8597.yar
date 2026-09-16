rule TTP_XOR_MULT_DOSStub_8597 {
  strings:
    $key_8597 = { d1 ff [2] a5 e7 [2] e2 e5 [2] a5 f4 [2] eb f8 [2] e7 f2 [2] f0 f9 [2] eb b7 [2] d6 }

  condition:
    any of them
}