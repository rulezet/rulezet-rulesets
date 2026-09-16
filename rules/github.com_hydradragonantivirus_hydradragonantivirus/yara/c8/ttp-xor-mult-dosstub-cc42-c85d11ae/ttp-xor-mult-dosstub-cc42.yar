rule TTP_XOR_MULT_DOSStub_cc42 {
  strings:
    $key_cc42 = { 98 2a [2] ec 32 [2] ab 30 [2] ec 21 [2] a2 2d [2] ae 27 [2] b9 2c [2] a2 62 [2] 9f }

  condition:
    any of them
}