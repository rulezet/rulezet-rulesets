rule TTP_XOR_MULT_DOSStub_b5f5 {
  strings:
    $key_b5f5 = { e1 9d [2] 95 85 [2] d2 87 [2] 95 96 [2] db 9a [2] d7 90 [2] c0 9b [2] db d5 [2] e6 }

  condition:
    any of them
}