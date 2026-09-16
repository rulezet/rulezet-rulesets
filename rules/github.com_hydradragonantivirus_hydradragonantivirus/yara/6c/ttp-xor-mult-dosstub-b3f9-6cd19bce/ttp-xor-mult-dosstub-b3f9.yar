rule TTP_XOR_MULT_DOSStub_b3f9 {
  strings:
    $key_b3f9 = { e7 91 [2] 93 89 [2] d4 8b [2] 93 9a [2] dd 96 [2] d1 9c [2] c6 97 [2] dd d9 [2] e0 }

  condition:
    any of them
}