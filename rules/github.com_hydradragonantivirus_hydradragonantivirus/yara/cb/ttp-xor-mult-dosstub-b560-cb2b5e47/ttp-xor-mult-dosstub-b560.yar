rule TTP_XOR_MULT_DOSStub_b560 {
  strings:
    $key_b560 = { e1 08 [2] 95 10 [2] d2 12 [2] 95 03 [2] db 0f [2] d7 05 [2] c0 0e [2] db 40 [2] e6 }

  condition:
    any of them
}