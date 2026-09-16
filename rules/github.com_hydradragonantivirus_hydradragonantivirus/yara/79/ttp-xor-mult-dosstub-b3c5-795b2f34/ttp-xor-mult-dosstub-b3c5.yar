rule TTP_XOR_MULT_DOSStub_b3c5 {
  strings:
    $key_b3c5 = { e7 ad [2] 93 b5 [2] d4 b7 [2] 93 a6 [2] dd aa [2] d1 a0 [2] c6 ab [2] dd e5 [2] e0 }

  condition:
    any of them
}