rule TTP_XOR_MULT_DOSStub_cc54 {
  strings:
    $key_cc54 = { 98 3c [2] ec 24 [2] ab 26 [2] ec 37 [2] a2 3b [2] ae 31 [2] b9 3a [2] a2 74 [2] 9f }

  condition:
    any of them
}