rule TTP_XOR_MULT_DOSStub_b5b7 {
  strings:
    $key_b5b7 = { e1 df [2] 95 c7 [2] d2 c5 [2] 95 d4 [2] db d8 [2] d7 d2 [2] c0 d9 [2] db 97 [2] e6 }

  condition:
    any of them
}