rule TTP_XOR_MULT_DOSStub_e668 {
  strings:
    $key_e668 = { b2 00 [2] c6 18 [2] 81 1a [2] c6 0b [2] 88 07 [2] 84 0d [2] 93 06 [2] 88 48 [2] b5 }

  condition:
    any of them
}