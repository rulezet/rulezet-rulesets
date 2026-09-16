rule TTP_XOR_MULT_DOSStub_e606 {
  strings:
    $key_e606 = { b2 6e [2] c6 76 [2] 81 74 [2] c6 65 [2] 88 69 [2] 84 63 [2] 93 68 [2] 88 26 [2] b5 }

  condition:
    any of them
}