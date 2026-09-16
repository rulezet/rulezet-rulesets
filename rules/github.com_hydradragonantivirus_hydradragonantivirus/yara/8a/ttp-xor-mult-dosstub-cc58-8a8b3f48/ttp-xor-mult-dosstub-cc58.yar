rule TTP_XOR_MULT_DOSStub_cc58 {
  strings:
    $key_cc58 = { 98 30 [2] ec 28 [2] ab 2a [2] ec 3b [2] a2 37 [2] ae 3d [2] b9 36 [2] a2 78 [2] 9f }

  condition:
    any of them
}