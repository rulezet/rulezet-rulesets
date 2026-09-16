rule TTP_XOR_MULT_DOSStub_b509 {
  strings:
    $key_b509 = { e1 61 [2] 95 79 [2] d2 7b [2] 95 6a [2] db 66 [2] d7 6c [2] c0 67 [2] db 29 [2] e6 }

  condition:
    any of them
}