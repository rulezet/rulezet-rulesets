rule TTP_XOR_MULT_DOSStub_b334 {
  strings:
    $key_b334 = { e7 5c [2] 93 44 [2] d4 46 [2] 93 57 [2] dd 5b [2] d1 51 [2] c6 5a [2] dd 14 [2] e0 }

  condition:
    any of them
}