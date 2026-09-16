rule TTP_XOR_MULT_DOSStub_b714 {
  strings:
    $key_b714 = { e3 7c [2] 97 64 [2] d0 66 [2] 97 77 [2] d9 7b [2] d5 71 [2] c2 7a [2] d9 34 [2] e4 }

  condition:
    any of them
}