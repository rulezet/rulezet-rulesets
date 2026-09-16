rule TTP_XOR_MULT_DOSStub_e630 {
  strings:
    $key_e630 = { b2 58 [2] c6 40 [2] 81 42 [2] c6 53 [2] 88 5f [2] 84 55 [2] 93 5e [2] 88 10 [2] b5 }

  condition:
    any of them
}