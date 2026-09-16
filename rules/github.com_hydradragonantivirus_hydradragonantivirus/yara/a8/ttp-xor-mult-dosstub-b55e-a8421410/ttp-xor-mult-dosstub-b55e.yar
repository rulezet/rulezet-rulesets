rule TTP_XOR_MULT_DOSStub_b55e {
  strings:
    $key_b55e = { e1 36 [2] 95 2e [2] d2 2c [2] 95 3d [2] db 31 [2] d7 3b [2] c0 30 [2] db 7e [2] e6 }

  condition:
    any of them
}