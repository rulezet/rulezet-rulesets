rule TTP_XOR_MULT_DOSStub_e6f0 {
  strings:
    $key_e6f0 = { b2 98 [2] c6 80 [2] 81 82 [2] c6 93 [2] 88 9f [2] 84 95 [2] 93 9e [2] 88 d0 [2] b5 }

  condition:
    any of them
}