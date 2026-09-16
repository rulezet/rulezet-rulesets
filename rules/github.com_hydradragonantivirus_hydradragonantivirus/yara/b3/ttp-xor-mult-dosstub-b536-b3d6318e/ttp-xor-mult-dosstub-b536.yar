rule TTP_XOR_MULT_DOSStub_b536 {
  strings:
    $key_b536 = { e1 5e [2] 95 46 [2] d2 44 [2] 95 55 [2] db 59 [2] d7 53 [2] c0 58 [2] db 16 [2] e6 }

  condition:
    any of them
}