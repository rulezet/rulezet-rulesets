rule TTP_XOR_MULT_DOSStub_ccf7 {
  strings:
    $key_ccf7 = { 98 9f [2] ec 87 [2] ab 85 [2] ec 94 [2] a2 98 [2] ae 92 [2] b9 99 [2] a2 d7 [2] 9f }

  condition:
    any of them
}