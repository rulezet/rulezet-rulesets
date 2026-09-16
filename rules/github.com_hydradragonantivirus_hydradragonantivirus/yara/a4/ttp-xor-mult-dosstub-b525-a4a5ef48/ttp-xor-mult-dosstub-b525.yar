rule TTP_XOR_MULT_DOSStub_b525 {
  strings:
    $key_b525 = { e1 4d [2] 95 55 [2] d2 57 [2] 95 46 [2] db 4a [2] d7 40 [2] c0 4b [2] db 05 [2] e6 }

  condition:
    any of them
}