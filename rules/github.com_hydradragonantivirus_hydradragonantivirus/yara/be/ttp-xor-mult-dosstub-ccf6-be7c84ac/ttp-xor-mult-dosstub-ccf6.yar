rule TTP_XOR_MULT_DOSStub_ccf6 {
  strings:
    $key_ccf6 = { 98 9e [2] ec 86 [2] ab 84 [2] ec 95 [2] a2 99 [2] ae 93 [2] b9 98 [2] a2 d6 [2] 9f }

  condition:
    any of them
}