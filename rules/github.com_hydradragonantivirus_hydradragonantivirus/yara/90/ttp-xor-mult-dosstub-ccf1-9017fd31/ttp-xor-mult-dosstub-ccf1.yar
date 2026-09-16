rule TTP_XOR_MULT_DOSStub_ccf1 {
  strings:
    $key_ccf1 = { 98 99 [2] ec 81 [2] ab 83 [2] ec 92 [2] a2 9e [2] ae 94 [2] b9 9f [2] a2 d1 [2] 9f }

  condition:
    any of them
}