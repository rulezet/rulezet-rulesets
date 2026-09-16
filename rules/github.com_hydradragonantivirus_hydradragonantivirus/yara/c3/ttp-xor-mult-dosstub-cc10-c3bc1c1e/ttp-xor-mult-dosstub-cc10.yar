rule TTP_XOR_MULT_DOSStub_cc10 {
  strings:
    $key_cc10 = { 98 78 [2] ec 60 [2] ab 62 [2] ec 73 [2] a2 7f [2] ae 75 [2] b9 7e [2] a2 30 [2] 9f }

  condition:
    any of them
}