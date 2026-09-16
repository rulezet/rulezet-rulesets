rule TTP_XOR_MULT_DOSStub_e600 {
  strings:
    $key_e600 = { b2 68 [2] c6 70 [2] 81 72 [2] c6 63 [2] 88 6f [2] 84 65 [2] 93 6e [2] 88 20 [2] b5 }

  condition:
    any of them
}