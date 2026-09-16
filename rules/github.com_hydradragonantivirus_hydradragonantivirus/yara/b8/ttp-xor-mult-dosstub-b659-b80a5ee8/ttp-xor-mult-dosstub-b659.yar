rule TTP_XOR_MULT_DOSStub_b659 {
  strings:
    $key_b659 = { e2 31 [2] 96 29 [2] d1 2b [2] 96 3a [2] d8 36 [2] d4 3c [2] c3 37 [2] d8 79 [2] e5 }

  condition:
    any of them
}