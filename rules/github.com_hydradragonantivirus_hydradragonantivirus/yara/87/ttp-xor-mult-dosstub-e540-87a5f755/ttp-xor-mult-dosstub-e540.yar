rule TTP_XOR_MULT_DOSStub_e540 {
  strings:
    $key_e540 = { b1 28 [2] c5 30 [2] 82 32 [2] c5 23 [2] 8b 2f [2] 87 25 [2] 90 2e [2] 8b 60 [2] b6 }

  condition:
    any of them
}