rule TTP_XOR_MULT_DOSStub_e632 {
  strings:
    $key_e632 = { b2 5a [2] c6 42 [2] 81 40 [2] c6 51 [2] 88 5d [2] 84 57 [2] 93 5c [2] 88 12 [2] b5 }

  condition:
    any of them
}