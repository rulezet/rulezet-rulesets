rule TTP_XOR_MULT_DOSStub_e565 {
  strings:
    $key_e565 = { b1 0d [2] c5 15 [2] 82 17 [2] c5 06 [2] 8b 0a [2] 87 00 [2] 90 0b [2] 8b 45 [2] b6 }

  condition:
    any of them
}