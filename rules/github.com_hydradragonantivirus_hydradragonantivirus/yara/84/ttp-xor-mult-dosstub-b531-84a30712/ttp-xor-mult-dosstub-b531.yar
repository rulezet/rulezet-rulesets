rule TTP_XOR_MULT_DOSStub_b531 {
  strings:
    $key_b531 = { e1 59 [2] 95 41 [2] d2 43 [2] 95 52 [2] db 5e [2] d7 54 [2] c0 5f [2] db 11 [2] e6 }

  condition:
    any of them
}