rule TTP_XOR_MULT_DOSStub_d679 {
  strings:
    $key_d679 = { 82 11 [2] f6 09 [2] b1 0b [2] f6 1a [2] b8 16 [2] b4 1c [2] a3 17 [2] b8 59 [2] 85 }

  condition:
    any of them
}