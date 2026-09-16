rule TTP_XOR_MULT_DOSStub_b562 {
  strings:
    $key_b562 = { e1 0a [2] 95 12 [2] d2 10 [2] 95 01 [2] db 0d [2] d7 07 [2] c0 0c [2] db 42 [2] e6 }

  condition:
    any of them
}