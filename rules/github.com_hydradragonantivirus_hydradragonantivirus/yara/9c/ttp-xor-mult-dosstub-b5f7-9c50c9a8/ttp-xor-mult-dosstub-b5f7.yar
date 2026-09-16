rule TTP_XOR_MULT_DOSStub_b5f7 {
  strings:
    $key_b5f7 = { e1 9f [2] 95 87 [2] d2 85 [2] 95 94 [2] db 98 [2] d7 92 [2] c0 99 [2] db d7 [2] e6 }

  condition:
    any of them
}