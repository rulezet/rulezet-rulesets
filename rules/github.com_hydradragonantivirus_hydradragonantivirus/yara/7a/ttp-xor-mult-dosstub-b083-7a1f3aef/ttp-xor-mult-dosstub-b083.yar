rule TTP_XOR_MULT_DOSStub_b083 {
  strings:
    $key_b083 = { e4 eb [2] 90 f3 [2] d7 f1 [2] 90 e0 [2] de ec [2] d2 e6 [2] c5 ed [2] de a3 [2] e3 }

  condition:
    any of them
}