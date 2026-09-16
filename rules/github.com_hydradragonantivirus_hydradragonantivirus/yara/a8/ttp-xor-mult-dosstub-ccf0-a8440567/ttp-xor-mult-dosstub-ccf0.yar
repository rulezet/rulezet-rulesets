rule TTP_XOR_MULT_DOSStub_ccf0 {
  strings:
    $key_ccf0 = { 98 98 [2] ec 80 [2] ab 82 [2] ec 93 [2] a2 9f [2] ae 95 [2] b9 9e [2] a2 d0 [2] 9f }

  condition:
    any of them
}