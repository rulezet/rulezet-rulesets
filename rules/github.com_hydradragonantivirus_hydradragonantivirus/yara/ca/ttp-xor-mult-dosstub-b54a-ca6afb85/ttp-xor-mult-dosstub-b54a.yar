rule TTP_XOR_MULT_DOSStub_b54a {
  strings:
    $key_b54a = { e1 22 [2] 95 3a [2] d2 38 [2] 95 29 [2] db 25 [2] d7 2f [2] c0 24 [2] db 6a [2] e6 }

  condition:
    any of them
}