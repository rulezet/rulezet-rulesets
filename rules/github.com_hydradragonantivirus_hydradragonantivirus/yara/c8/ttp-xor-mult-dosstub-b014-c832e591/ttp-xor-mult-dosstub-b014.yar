rule TTP_XOR_MULT_DOSStub_b014 {
  strings:
    $key_b014 = { e4 7c [2] 90 64 [2] d7 66 [2] 90 77 [2] de 7b [2] d2 71 [2] c5 7a [2] de 34 [2] e3 }

  condition:
    any of them
}