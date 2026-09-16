rule TTP_XOR_MULT_DOSStub_b508 {
  strings:
    $key_b508 = { e1 60 [2] 95 78 [2] d2 7a [2] 95 6b [2] db 67 [2] d7 6d [2] c0 66 [2] db 28 [2] e6 }

  condition:
    any of them
}