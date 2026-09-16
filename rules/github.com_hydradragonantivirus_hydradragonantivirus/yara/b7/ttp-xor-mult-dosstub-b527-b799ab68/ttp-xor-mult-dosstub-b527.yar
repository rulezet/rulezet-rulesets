rule TTP_XOR_MULT_DOSStub_b527 {
  strings:
    $key_b527 = { e1 4f [2] 95 57 [2] d2 55 [2] 95 44 [2] db 48 [2] d7 42 [2] c0 49 [2] db 07 [2] e6 }

  condition:
    any of them
}