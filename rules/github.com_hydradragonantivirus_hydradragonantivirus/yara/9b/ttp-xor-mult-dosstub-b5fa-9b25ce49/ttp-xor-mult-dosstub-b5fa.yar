rule TTP_XOR_MULT_DOSStub_b5fa {
  strings:
    $key_b5fa = { e1 92 [2] 95 8a [2] d2 88 [2] 95 99 [2] db 95 [2] d7 9f [2] c0 94 [2] db da [2] e6 }

  condition:
    any of them
}