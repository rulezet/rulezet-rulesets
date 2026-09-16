rule TTP_XOR_MULT_DOSStub_b312 {
  strings:
    $key_b312 = { e7 7a [2] 93 62 [2] d4 60 [2] 93 71 [2] dd 7d [2] d1 77 [2] c6 7c [2] dd 32 [2] e0 }

  condition:
    any of them
}