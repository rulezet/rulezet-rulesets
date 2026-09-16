rule TTP_XOR_MULT_DOSStub_cc15 {
  strings:
    $key_cc15 = { 98 7d [2] ec 65 [2] ab 67 [2] ec 76 [2] a2 7a [2] ae 70 [2] b9 7b [2] a2 35 [2] 9f }

  condition:
    any of them
}