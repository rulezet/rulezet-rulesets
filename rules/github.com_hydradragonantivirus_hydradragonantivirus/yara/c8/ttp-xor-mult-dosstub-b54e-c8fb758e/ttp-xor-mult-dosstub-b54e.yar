rule TTP_XOR_MULT_DOSStub_b54e {
  strings:
    $key_b54e = { e1 26 [2] 95 3e [2] d2 3c [2] 95 2d [2] db 21 [2] d7 2b [2] c0 20 [2] db 6e [2] e6 }

  condition:
    any of them
}