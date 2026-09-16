rule TTP_XOR_MULT_DOSStub_cc13 {
  strings:
    $key_cc13 = { 98 7b [2] ec 63 [2] ab 61 [2] ec 70 [2] a2 7c [2] ae 76 [2] b9 7d [2] a2 33 [2] 9f }

  condition:
    any of them
}