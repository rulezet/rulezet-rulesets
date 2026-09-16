rule TTP_XOR_MULT_DOSStub_e6f8 {
  strings:
    $key_e6f8 = { b2 90 [2] c6 88 [2] 81 8a [2] c6 9b [2] 88 97 [2] 84 9d [2] 93 96 [2] 88 d8 [2] b5 }

  condition:
    any of them
}