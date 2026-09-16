rule TTP_XOR_MULT_DOSStub_e651 {
  strings:
    $key_e651 = { b2 39 [2] c6 21 [2] 81 23 [2] c6 32 [2] 88 3e [2] 84 34 [2] 93 3f [2] 88 71 [2] b5 }

  condition:
    any of them
}