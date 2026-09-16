rule TTP_XOR_MULT_DOSStub_e662 {
  strings:
    $key_e662 = { b2 0a [2] c6 12 [2] 81 10 [2] c6 01 [2] 88 0d [2] 84 07 [2] 93 0c [2] 88 42 [2] b5 }

  condition:
    any of them
}