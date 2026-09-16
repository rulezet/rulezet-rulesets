rule TTP_XOR_MULT_DOSStub_e647 {
  strings:
    $key_e647 = { b2 2f [2] c6 37 [2] 81 35 [2] c6 24 [2] 88 28 [2] 84 22 [2] 93 29 [2] 88 67 [2] b5 }

  condition:
    any of them
}