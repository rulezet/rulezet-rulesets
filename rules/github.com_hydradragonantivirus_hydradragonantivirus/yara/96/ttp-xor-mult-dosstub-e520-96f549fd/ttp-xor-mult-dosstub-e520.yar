rule TTP_XOR_MULT_DOSStub_e520 {
  strings:
    $key_e520 = { b1 48 [2] c5 50 [2] 82 52 [2] c5 43 [2] 8b 4f [2] 87 45 [2] 90 4e [2] 8b 00 [2] b6 }

  condition:
    any of them
}