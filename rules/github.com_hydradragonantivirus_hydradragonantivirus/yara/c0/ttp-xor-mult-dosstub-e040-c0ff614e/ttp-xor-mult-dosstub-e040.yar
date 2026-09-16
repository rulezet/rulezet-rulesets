rule TTP_XOR_MULT_DOSStub_e040 {
  strings:
    $key_e040 = { b4 28 [2] c0 30 [2] 87 32 [2] c0 23 [2] 8e 2f [2] 82 25 [2] 95 2e [2] 8e 60 [2] b3 }

  condition:
    any of them
}