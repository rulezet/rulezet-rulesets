rule TTP_XOR_MULT_DOSStub_e5f1 {
  strings:
    $key_e5f1 = { b1 99 [2] c5 81 [2] 82 83 [2] c5 92 [2] 8b 9e [2] 87 94 [2] 90 9f [2] 8b d1 [2] b6 }

  condition:
    any of them
}