rule TTP_XOR_MULT_DOSStub_e050 {
  strings:
    $key_e050 = { b4 38 [2] c0 20 [2] 87 22 [2] c0 33 [2] 8e 3f [2] 82 35 [2] 95 3e [2] 8e 70 [2] b3 }

  condition:
    any of them
}