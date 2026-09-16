rule TTP_XOR_MULT_DOSStub_b51a {
  strings:
    $key_b51a = { e1 72 [2] 95 6a [2] d2 68 [2] 95 79 [2] db 75 [2] d7 7f [2] c0 74 [2] db 3a [2] e6 }

  condition:
    any of them
}