rule TTP_XOR_MULT_DOSStub_e619 {
  strings:
    $key_e619 = { b2 71 [2] c6 69 [2] 81 6b [2] c6 7a [2] 88 76 [2] 84 7c [2] 93 77 [2] 88 39 [2] b5 }

  condition:
    any of them
}