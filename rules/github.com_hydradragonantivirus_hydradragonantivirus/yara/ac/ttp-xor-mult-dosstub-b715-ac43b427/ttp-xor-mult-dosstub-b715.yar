rule TTP_XOR_MULT_DOSStub_b715 {
  strings:
    $key_b715 = { e3 7d [2] 97 65 [2] d0 67 [2] 97 76 [2] d9 7a [2] d5 70 [2] c2 7b [2] d9 35 [2] e4 }

  condition:
    any of them
}