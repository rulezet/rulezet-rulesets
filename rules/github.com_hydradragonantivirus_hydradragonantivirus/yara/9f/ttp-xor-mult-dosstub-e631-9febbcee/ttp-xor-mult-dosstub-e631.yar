rule TTP_XOR_MULT_DOSStub_e631 {
  strings:
    $key_e631 = { b2 59 [2] c6 41 [2] 81 43 [2] c6 52 [2] 88 5e [2] 84 54 [2] 93 5f [2] 88 11 [2] b5 }

  condition:
    any of them
}