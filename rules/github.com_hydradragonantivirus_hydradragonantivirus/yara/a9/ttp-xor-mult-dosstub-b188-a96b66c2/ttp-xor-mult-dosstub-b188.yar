rule TTP_XOR_MULT_DOSStub_b188 {
  strings:
    $key_b188 = { e5 e0 [2] 91 f8 [2] d6 fa [2] 91 eb [2] df e7 [2] d3 ed [2] c4 e6 [2] df a8 [2] e2 }

  condition:
    any of them
}