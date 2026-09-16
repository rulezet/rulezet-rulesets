rule TTP_XOR_MULT_DOSStub_cda9 {
  strings:
    $key_cda9 = { 99 c1 [2] ed d9 [2] aa db [2] ed ca [2] a3 c6 [2] af cc [2] b8 c7 [2] a3 89 [2] 9e }

  condition:
    any of them
}