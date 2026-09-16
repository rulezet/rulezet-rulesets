rule TTP_XOR_MULT_DOSStub_cc87 {
  strings:
    $key_cc87 = { 98 ef [2] ec f7 [2] ab f5 [2] ec e4 [2] a2 e8 [2] ae e2 [2] b9 e9 [2] a2 a7 [2] 9f }

  condition:
    any of them
}