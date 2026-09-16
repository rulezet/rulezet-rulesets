rule TTP_XOR_MULT_DOSStub_e6e5 {
  strings:
    $key_e6e5 = { b2 8d [2] c6 95 [2] 81 97 [2] c6 86 [2] 88 8a [2] 84 80 [2] 93 8b [2] 88 c5 [2] b5 }

  condition:
    any of them
}