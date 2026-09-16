rule TTP_XOR_MULT_DOSStub_e7f1 {
  strings:
    $key_e7f1 = { b3 99 [2] c7 81 [2] 80 83 [2] c7 92 [2] 89 9e [2] 85 94 [2] 92 9f [2] 89 d1 [2] b4 }

  condition:
    any of them
}