rule TTP_XOR_MULT_DOSStub_e537 {
  strings:
    $key_e537 = { b1 5f [2] c5 47 [2] 82 45 [2] c5 54 [2] 8b 58 [2] 87 52 [2] 90 59 [2] 8b 17 [2] b6 }

  condition:
    any of them
}