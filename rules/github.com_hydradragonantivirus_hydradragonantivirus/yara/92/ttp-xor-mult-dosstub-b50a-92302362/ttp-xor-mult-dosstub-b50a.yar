rule TTP_XOR_MULT_DOSStub_b50a {
  strings:
    $key_b50a = { e1 62 [2] 95 7a [2] d2 78 [2] 95 69 [2] db 65 [2] d7 6f [2] c0 64 [2] db 2a [2] e6 }

  condition:
    any of them
}