rule TTP_XOR_MULT_DOSStub_b57f {
  strings:
    $key_b57f = { e1 17 [2] 95 0f [2] d2 0d [2] 95 1c [2] db 10 [2] d7 1a [2] c0 11 [2] db 5f [2] e6 }

  condition:
    any of them
}