rule TTP_XOR_MULT_DOSStub_ccf5 {
  strings:
    $key_ccf5 = { 98 9d [2] ec 85 [2] ab 87 [2] ec 96 [2] a2 9a [2] ae 90 [2] b9 9b [2] a2 d5 [2] 9f }

  condition:
    any of them
}