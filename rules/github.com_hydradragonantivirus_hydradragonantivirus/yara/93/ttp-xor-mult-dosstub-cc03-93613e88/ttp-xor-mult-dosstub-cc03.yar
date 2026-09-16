rule TTP_XOR_MULT_DOSStub_cc03 {
  strings:
    $key_cc03 = { 98 6b [2] ec 73 [2] ab 71 [2] ec 60 [2] a2 6c [2] ae 66 [2] b9 6d [2] a2 23 [2] 9f }

  condition:
    any of them
}