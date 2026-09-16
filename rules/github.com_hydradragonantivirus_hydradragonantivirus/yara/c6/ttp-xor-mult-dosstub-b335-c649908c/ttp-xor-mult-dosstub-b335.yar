rule TTP_XOR_MULT_DOSStub_b335 {
  strings:
    $key_b335 = { e7 5d [2] 93 45 [2] d4 47 [2] 93 56 [2] dd 5a [2] d1 50 [2] c6 5b [2] dd 15 [2] e0 }

  condition:
    any of them
}