rule TTP_XOR_MULT_DOSStub_e635 {
  strings:
    $key_e635 = { b2 5d [2] c6 45 [2] 81 47 [2] c6 56 [2] 88 5a [2] 84 50 [2] 93 5b [2] 88 15 [2] b5 }

  condition:
    any of them
}