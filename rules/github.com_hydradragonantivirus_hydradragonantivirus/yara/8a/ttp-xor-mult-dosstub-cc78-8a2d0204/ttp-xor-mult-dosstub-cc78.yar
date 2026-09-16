rule TTP_XOR_MULT_DOSStub_cc78 {
  strings:
    $key_cc78 = { 98 10 [2] ec 08 [2] ab 0a [2] ec 1b [2] a2 17 [2] ae 1d [2] b9 16 [2] a2 58 [2] 9f }

  condition:
    any of them
}