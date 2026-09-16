rule TTP_XOR_MULT_DOSStub_ca87 {
  strings:
    $key_ca87 = { 9e ef [2] ea f7 [2] ad f5 [2] ea e4 [2] a4 e8 [2] a8 e2 [2] bf e9 [2] a4 a7 [2] 99 }

  condition:
    any of them
}