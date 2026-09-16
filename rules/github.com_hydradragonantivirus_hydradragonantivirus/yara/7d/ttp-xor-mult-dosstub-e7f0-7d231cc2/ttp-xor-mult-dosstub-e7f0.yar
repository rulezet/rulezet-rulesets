rule TTP_XOR_MULT_DOSStub_e7f0 {
  strings:
    $key_e7f0 = { b3 98 [2] c7 80 [2] 80 82 [2] c7 93 [2] 89 9f [2] 85 95 [2] 92 9e [2] 89 d0 [2] b4 }

  condition:
    any of them
}