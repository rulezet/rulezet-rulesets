rule TTP_XOR_MULT_DOSStub_b499 {
  strings:
    $key_b499 = { e0 f1 [2] 94 e9 [2] d3 eb [2] 94 fa [2] da f6 [2] d6 fc [2] c1 f7 [2] da b9 [2] e7 }

  condition:
    any of them
}