rule TTP_XOR_MULT_DOSStub_e605 {
  strings:
    $key_e605 = { b2 6d [2] c6 75 [2] 81 77 [2] c6 66 [2] 88 6a [2] 84 60 [2] 93 6b [2] 88 25 [2] b5 }

  condition:
    any of them
}