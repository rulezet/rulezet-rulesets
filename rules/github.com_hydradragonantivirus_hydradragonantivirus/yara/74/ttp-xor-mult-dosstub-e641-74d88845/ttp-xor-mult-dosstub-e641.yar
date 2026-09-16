rule TTP_XOR_MULT_DOSStub_e641 {
  strings:
    $key_e641 = { b2 29 [2] c6 31 [2] 81 33 [2] c6 22 [2] 88 2e [2] 84 24 [2] 93 2f [2] 88 61 [2] b5 }

  condition:
    any of them
}