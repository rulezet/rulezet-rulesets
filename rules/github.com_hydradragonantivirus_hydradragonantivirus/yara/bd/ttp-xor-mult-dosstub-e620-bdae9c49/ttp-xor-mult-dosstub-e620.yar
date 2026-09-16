rule TTP_XOR_MULT_DOSStub_e620 {
  strings:
    $key_e620 = { b2 48 [2] c6 50 [2] 81 52 [2] c6 43 [2] 88 4f [2] 84 45 [2] 93 4e [2] 88 00 [2] b5 }

  condition:
    any of them
}