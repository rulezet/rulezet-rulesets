rule TTP_XOR_MULT_DOSStub_b55c {
  strings:
    $key_b55c = { e1 34 [2] 95 2c [2] d2 2e [2] 95 3f [2] db 33 [2] d7 39 [2] c0 32 [2] db 7c [2] e6 }

  condition:
    any of them
}