rule TTP_XOR_MULT_DOSStub_b541 {
  strings:
    $key_b541 = { e1 29 [2] 95 31 [2] d2 33 [2] 95 22 [2] db 2e [2] d7 24 [2] c0 2f [2] db 61 [2] e6 }

  condition:
    any of them
}