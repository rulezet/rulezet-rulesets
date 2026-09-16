rule TTP_XOR_MULT_DOSStub_b0f5 {
  strings:
    $key_b0f5 = { e4 9d [2] 90 85 [2] d7 87 [2] 90 96 [2] de 9a [2] d2 90 [2] c5 9b [2] de d5 [2] e3 }

  condition:
    any of them
}