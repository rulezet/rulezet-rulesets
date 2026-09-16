rule TTP_XOR_MULT_DOSStub_e5f0 {
  strings:
    $key_e5f0 = { b1 98 [2] c5 80 [2] 82 82 [2] c5 93 [2] 8b 9f [2] 87 95 [2] 90 9e [2] 8b d0 [2] b6 }

  condition:
    any of them
}