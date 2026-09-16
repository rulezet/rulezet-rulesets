rule TTP_XOR_MULT_DOSStub_b6f5 {
  strings:
    $key_b6f5 = { e2 9d [2] 96 85 [2] d1 87 [2] 96 96 [2] d8 9a [2] d4 90 [2] c3 9b [2] d8 d5 [2] e5 }

  condition:
    any of them
}