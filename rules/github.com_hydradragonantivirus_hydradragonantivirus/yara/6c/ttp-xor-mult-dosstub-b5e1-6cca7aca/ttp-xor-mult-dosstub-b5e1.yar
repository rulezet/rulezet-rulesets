rule TTP_XOR_MULT_DOSStub_b5e1 {
  strings:
    $key_b5e1 = { e1 89 [2] 95 91 [2] d2 93 [2] 95 82 [2] db 8e [2] d7 84 [2] c0 8f [2] db c1 [2] e6 }

  condition:
    any of them
}