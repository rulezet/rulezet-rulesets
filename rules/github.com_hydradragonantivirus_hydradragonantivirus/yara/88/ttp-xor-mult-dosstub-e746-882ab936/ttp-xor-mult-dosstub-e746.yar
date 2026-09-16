rule TTP_XOR_MULT_DOSStub_e746 {
  strings:
    $key_e746 = { b3 2e [2] c7 36 [2] 80 34 [2] c7 25 [2] 89 29 [2] 85 23 [2] 92 28 [2] 89 66 [2] b4 }

  condition:
    any of them
}