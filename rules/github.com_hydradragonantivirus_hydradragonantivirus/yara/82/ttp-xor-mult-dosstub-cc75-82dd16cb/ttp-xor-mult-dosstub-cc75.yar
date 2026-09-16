rule TTP_XOR_MULT_DOSStub_cc75 {
  strings:
    $key_cc75 = { 98 1d [2] ec 05 [2] ab 07 [2] ec 16 [2] a2 1a [2] ae 10 [2] b9 1b [2] a2 55 [2] 9f }

  condition:
    any of them
}