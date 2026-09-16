rule TTP_XOR_MULT_DOSStub_b6f2 {
  strings:
    $key_b6f2 = { e2 9a [2] 96 82 [2] d1 80 [2] 96 91 [2] d8 9d [2] d4 97 [2] c3 9c [2] d8 d2 [2] e5 }

  condition:
    any of them
}