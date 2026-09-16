rule TTP_XOR_MULT_DOSStub_e65c {
  strings:
    $key_e65c = { b2 34 [2] c6 2c [2] 81 2e [2] c6 3f [2] 88 33 [2] 84 39 [2] 93 32 [2] 88 7c [2] b5 }

  condition:
    any of them
}