rule TTP_XOR_MULT_DOSStub_cda6 {
  strings:
    $key_cda6 = { 99 ce [2] ed d6 [2] aa d4 [2] ed c5 [2] a3 c9 [2] af c3 [2] b8 c8 [2] a3 86 [2] 9e }

  condition:
    any of them
}