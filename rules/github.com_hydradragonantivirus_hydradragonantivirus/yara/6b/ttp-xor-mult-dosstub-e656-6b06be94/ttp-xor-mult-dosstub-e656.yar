rule TTP_XOR_MULT_DOSStub_e656 {
  strings:
    $key_e656 = { b2 3e [2] c6 26 [2] 81 24 [2] c6 35 [2] 88 39 [2] 84 33 [2] 93 38 [2] 88 76 [2] b5 }

  condition:
    any of them
}