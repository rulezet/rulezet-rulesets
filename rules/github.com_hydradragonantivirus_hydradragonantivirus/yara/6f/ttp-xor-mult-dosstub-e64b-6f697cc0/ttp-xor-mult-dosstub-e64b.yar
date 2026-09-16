rule TTP_XOR_MULT_DOSStub_e64b {
  strings:
    $key_e64b = { b2 23 [2] c6 3b [2] 81 39 [2] c6 28 [2] 88 24 [2] 84 2e [2] 93 25 [2] 88 6b [2] b5 }

  condition:
    any of them
}