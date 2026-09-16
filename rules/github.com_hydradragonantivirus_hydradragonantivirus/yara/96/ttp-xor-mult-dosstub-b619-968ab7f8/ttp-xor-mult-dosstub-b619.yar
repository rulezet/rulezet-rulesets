rule TTP_XOR_MULT_DOSStub_b619 {
  strings:
    $key_b619 = { e2 71 [2] 96 69 [2] d1 6b [2] 96 7a [2] d8 76 [2] d4 7c [2] c3 77 [2] d8 39 [2] e5 }

  condition:
    any of them
}