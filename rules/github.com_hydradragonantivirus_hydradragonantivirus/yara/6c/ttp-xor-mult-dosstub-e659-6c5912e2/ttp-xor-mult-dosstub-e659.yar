rule TTP_XOR_MULT_DOSStub_e659 {
  strings:
    $key_e659 = { b2 31 [2] c6 29 [2] 81 2b [2] c6 3a [2] 88 36 [2] 84 3c [2] 93 37 [2] 88 79 [2] b5 }

  condition:
    any of them
}