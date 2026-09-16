rule TTP_XOR_MULT_DOSStub_cc65 {
  strings:
    $key_cc65 = { 98 0d [2] ec 15 [2] ab 17 [2] ec 06 [2] a2 0a [2] ae 00 [2] b9 0b [2] a2 45 [2] 9f }

  condition:
    any of them
}