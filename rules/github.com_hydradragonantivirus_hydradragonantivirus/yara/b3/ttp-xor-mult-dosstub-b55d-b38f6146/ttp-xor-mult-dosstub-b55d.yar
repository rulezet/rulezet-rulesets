rule TTP_XOR_MULT_DOSStub_b55d {
  strings:
    $key_b55d = { e1 35 [2] 95 2d [2] d2 2f [2] 95 3e [2] db 32 [2] d7 38 [2] c0 33 [2] db 7d [2] e6 }

  condition:
    any of them
}