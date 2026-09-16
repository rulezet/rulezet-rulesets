rule TTP_XOR_MULT_DOSStub_e7f6 {
  strings:
    $key_e7f6 = { b3 9e [2] c7 86 [2] 80 84 [2] c7 95 [2] 89 99 [2] 85 93 [2] 92 98 [2] 89 d6 [2] b4 }

  condition:
    any of them
}