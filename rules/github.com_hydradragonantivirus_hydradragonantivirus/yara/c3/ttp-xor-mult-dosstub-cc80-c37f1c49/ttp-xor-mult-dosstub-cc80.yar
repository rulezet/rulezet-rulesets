rule TTP_XOR_MULT_DOSStub_cc80 {
  strings:
    $key_cc80 = { 98 e8 [2] ec f0 [2] ab f2 [2] ec e3 [2] a2 ef [2] ae e5 [2] b9 ee [2] a2 a0 [2] 9f }

  condition:
    any of them
}