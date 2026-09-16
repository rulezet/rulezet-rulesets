rule TTP_XOR_MULT_DOSStub_cc14 {
  strings:
    $key_cc14 = { 98 7c [2] ec 64 [2] ab 66 [2] ec 77 [2] a2 7b [2] ae 71 [2] b9 7a [2] a2 34 [2] 9f }

  condition:
    any of them
}