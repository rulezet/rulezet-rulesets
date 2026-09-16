rule TTP_XOR_MULT_DOSStub_ccf8 {
  strings:
    $key_ccf8 = { 98 90 [2] ec 88 [2] ab 8a [2] ec 9b [2] a2 97 [2] ae 9d [2] b9 96 [2] a2 d8 [2] 9f }

  condition:
    any of them
}