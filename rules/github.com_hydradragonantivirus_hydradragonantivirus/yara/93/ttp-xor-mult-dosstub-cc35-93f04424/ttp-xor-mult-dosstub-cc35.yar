rule TTP_XOR_MULT_DOSStub_cc35 {
  strings:
    $key_cc35 = { 98 5d [2] ec 45 [2] ab 47 [2] ec 56 [2] a2 5a [2] ae 50 [2] b9 5b [2] a2 15 [2] 9f }

  condition:
    any of them
}