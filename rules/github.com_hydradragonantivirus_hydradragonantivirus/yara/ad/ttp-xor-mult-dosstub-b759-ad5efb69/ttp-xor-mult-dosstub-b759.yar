rule TTP_XOR_MULT_DOSStub_b759 {
  strings:
    $key_b759 = { e3 31 [2] 97 29 [2] d0 2b [2] 97 3a [2] d9 36 [2] d5 3c [2] c2 37 [2] d9 79 [2] e4 }

  condition:
    any of them
}