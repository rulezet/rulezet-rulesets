rule TTP_XOR_MULT_DOSStub_b54c {
  strings:
    $key_b54c = { e1 24 [2] 95 3c [2] d2 3e [2] 95 2f [2] db 23 [2] d7 29 [2] c0 22 [2] db 6c [2] e6 }

  condition:
    any of them
}