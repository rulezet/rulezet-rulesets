rule TTP_XOR_MULT_DOSStub_b5e2 {
  strings:
    $key_b5e2 = { e1 8a [2] 95 92 [2] d2 90 [2] 95 81 [2] db 8d [2] d7 87 [2] c0 8c [2] db c2 [2] e6 }

  condition:
    any of them
}