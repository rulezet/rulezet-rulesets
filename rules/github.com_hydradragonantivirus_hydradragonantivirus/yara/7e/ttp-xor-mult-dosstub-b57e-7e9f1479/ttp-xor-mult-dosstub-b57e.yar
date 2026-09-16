rule TTP_XOR_MULT_DOSStub_b57e {
  strings:
    $key_b57e = { e1 16 [2] 95 0e [2] d2 0c [2] 95 1d [2] db 11 [2] d7 1b [2] c0 10 [2] db 5e [2] e6 }

  condition:
    any of them
}