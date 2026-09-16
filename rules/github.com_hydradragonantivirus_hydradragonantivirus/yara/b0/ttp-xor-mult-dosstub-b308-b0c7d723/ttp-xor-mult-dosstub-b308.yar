rule TTP_XOR_MULT_DOSStub_b308 {
  strings:
    $key_b308 = { e7 60 [2] 93 78 [2] d4 7a [2] 93 6b [2] dd 67 [2] d1 6d [2] c6 66 [2] dd 28 [2] e0 }

  condition:
    any of them
}