rule TTP_XOR_MULT_DOSStub_e570 {
  strings:
    $key_e570 = { b1 18 [2] c5 00 [2] 82 02 [2] c5 13 [2] 8b 1f [2] 87 15 [2] 90 1e [2] 8b 50 [2] b6 }

  condition:
    any of them
}