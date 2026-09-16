rule TTP_XOR_MULT_DOSStub_b5b1 {
  strings:
    $key_b5b1 = { e1 d9 [2] 95 c1 [2] d2 c3 [2] 95 d2 [2] db de [2] d7 d4 [2] c0 df [2] db 91 [2] e6 }

  condition:
    any of them
}