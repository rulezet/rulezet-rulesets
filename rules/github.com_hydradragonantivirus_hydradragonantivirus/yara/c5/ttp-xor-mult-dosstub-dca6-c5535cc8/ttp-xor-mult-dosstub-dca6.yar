rule TTP_XOR_MULT_DOSStub_dca6 {
  strings:
    $key_dca6 = { 88 ce [2] fc d6 [2] bb d4 [2] fc c5 [2] b2 c9 [2] be c3 [2] a9 c8 [2] b2 86 [2] 8f }

  condition:
    any of them
}