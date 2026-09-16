rule TTP_XOR_MULT_DOSStub_e614 {
  strings:
    $key_e614 = { b2 7c [2] c6 64 [2] 81 66 [2] c6 77 [2] 88 7b [2] 84 71 [2] 93 7a [2] 88 34 [2] b5 }

  condition:
    any of them
}