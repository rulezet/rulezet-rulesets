rule TTP_XOR_MULT_DOSStub_b52c {
  strings:
    $key_b52c = { e1 44 [2] 95 5c [2] d2 5e [2] 95 4f [2] db 43 [2] d7 49 [2] c0 42 [2] db 0c [2] e6 }

  condition:
    any of them
}