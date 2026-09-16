rule TTP_XOR_MULT_DOSStub_b399 {
  strings:
    $key_b399 = { e7 f1 [2] 93 e9 [2] d4 eb [2] 93 fa [2] dd f6 [2] d1 fc [2] c6 f7 [2] dd b9 [2] e0 }

  condition:
    any of them
}