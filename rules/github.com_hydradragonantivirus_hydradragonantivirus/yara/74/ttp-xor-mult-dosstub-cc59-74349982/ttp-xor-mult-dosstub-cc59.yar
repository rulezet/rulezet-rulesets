rule TTP_XOR_MULT_DOSStub_cc59 {
  strings:
    $key_cc59 = { 98 31 [2] ec 29 [2] ab 2b [2] ec 3a [2] a2 36 [2] ae 3c [2] b9 37 [2] a2 79 [2] 9f }

  condition:
    any of them
}