rule TTP_XOR_MULT_DOSStub_b1c3 {
  strings:
    $key_b1c3 = { e5 ab [2] 91 b3 [2] d6 b1 [2] 91 a0 [2] df ac [2] d3 a6 [2] c4 ad [2] df e3 [2] e2 }

  condition:
    any of them
}