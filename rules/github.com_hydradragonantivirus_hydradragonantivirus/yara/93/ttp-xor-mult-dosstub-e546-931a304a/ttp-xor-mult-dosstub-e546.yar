rule TTP_XOR_MULT_DOSStub_e546 {
  strings:
    $key_e546 = { b1 2e [2] c5 36 [2] 82 34 [2] c5 25 [2] 8b 29 [2] 87 23 [2] 90 28 [2] 8b 66 [2] b6 }

  condition:
    any of them
}