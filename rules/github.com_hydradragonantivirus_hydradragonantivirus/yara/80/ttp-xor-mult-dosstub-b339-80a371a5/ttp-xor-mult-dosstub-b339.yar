rule TTP_XOR_MULT_DOSStub_b339 {
  strings:
    $key_b339 = { e7 51 [2] 93 49 [2] d4 4b [2] 93 5a [2] dd 56 [2] d1 5c [2] c6 57 [2] dd 19 [2] e0 }

  condition:
    any of them
}