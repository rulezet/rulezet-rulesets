rule TTP_XOR_MULT_DOSStub_e639 {
  strings:
    $key_e639 = { b2 51 [2] c6 49 [2] 81 4b [2] c6 5a [2] 88 56 [2] 84 5c [2] 93 57 [2] 88 19 [2] b5 }

  condition:
    any of them
}