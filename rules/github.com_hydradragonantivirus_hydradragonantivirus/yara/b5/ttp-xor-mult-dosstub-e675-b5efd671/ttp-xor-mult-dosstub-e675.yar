rule TTP_XOR_MULT_DOSStub_e675 {
  strings:
    $key_e675 = { b2 1d [2] c6 05 [2] 81 07 [2] c6 16 [2] 88 1a [2] 84 10 [2] 93 1b [2] 88 55 [2] b5 }

  condition:
    any of them
}