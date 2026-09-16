rule TTP_XOR_MULT_DOSStub_b1c8 {
  strings:
    $key_b1c8 = { e5 a0 [2] 91 b8 [2] d6 ba [2] 91 ab [2] df a7 [2] d3 ad [2] c4 a6 [2] df e8 [2] e2 }

  condition:
    any of them
}