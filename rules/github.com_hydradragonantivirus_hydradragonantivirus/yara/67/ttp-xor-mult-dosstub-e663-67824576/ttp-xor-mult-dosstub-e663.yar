rule TTP_XOR_MULT_DOSStub_e663 {
  strings:
    $key_e663 = { b2 0b [2] c6 13 [2] 81 11 [2] c6 00 [2] 88 0c [2] 84 06 [2] 93 0d [2] 88 43 [2] b5 }

  condition:
    any of them
}