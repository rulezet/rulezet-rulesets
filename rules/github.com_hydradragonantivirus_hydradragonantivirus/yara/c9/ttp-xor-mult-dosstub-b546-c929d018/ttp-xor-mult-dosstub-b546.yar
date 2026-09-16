rule TTP_XOR_MULT_DOSStub_b546 {
  strings:
    $key_b546 = { e1 2e [2] 95 36 [2] d2 34 [2] 95 25 [2] db 29 [2] d7 23 [2] c0 28 [2] db 66 [2] e6 }

  condition:
    any of them
}