rule TTP_XOR_MULT_DOSStub_cc76 {
  strings:
    $key_cc76 = { 98 1e [2] ec 06 [2] ab 04 [2] ec 15 [2] a2 19 [2] ae 13 [2] b9 18 [2] a2 56 [2] 9f }

  condition:
    any of them
}