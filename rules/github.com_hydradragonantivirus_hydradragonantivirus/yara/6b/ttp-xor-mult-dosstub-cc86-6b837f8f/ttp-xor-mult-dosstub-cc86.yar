rule TTP_XOR_MULT_DOSStub_cc86 {
  strings:
    $key_cc86 = { 98 ee [2] ec f6 [2] ab f4 [2] ec e5 [2] a2 e9 [2] ae e3 [2] b9 e8 [2] a2 a6 [2] 9f }

  condition:
    any of them
}