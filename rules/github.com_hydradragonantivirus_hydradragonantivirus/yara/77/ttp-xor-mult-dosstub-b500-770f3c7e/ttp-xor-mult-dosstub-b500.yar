rule TTP_XOR_MULT_DOSStub_b500 {
  strings:
    $key_b500 = { e1 68 [2] 95 70 [2] d2 72 [2] 95 63 [2] db 6f [2] d7 65 [2] c0 6e [2] db 20 [2] e6 }

  condition:
    any of them
}