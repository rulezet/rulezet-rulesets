rule TTP_XOR_MULT_DOSStub_b55a {
  strings:
    $key_b55a = { e1 32 [2] 95 2a [2] d2 28 [2] 95 39 [2] db 35 [2] d7 3f [2] c0 34 [2] db 7a [2] e6 }

  condition:
    any of them
}